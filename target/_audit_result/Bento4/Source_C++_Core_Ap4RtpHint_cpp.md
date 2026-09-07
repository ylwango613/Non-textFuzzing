I now have complete context. Let me compile the analysis:

**Group 1 analysis (lines 50–75, `AP4_RtpSampleData` constructor):**
- `size` comes from `m_CurrentHintSample.GetSize()` → `stsz` box → fully attacker-controlled.
- `extra_data_start - start` is the actual bytes consumed by packet parsing (all in uint64 `AP4_Position`).
- Line 70: `AP4_Size extra_data_size = size - (AP4_UI32)(extra_data_start-start);` — if the packet-parsing loop reads more bytes than `size`, `(AP4_UI32)(extra_data_start-start) > size` and the unsigned subtraction underflows to ~4 GB.
- Line 72: `m_ExtraData.SetDataSize(extra_data_size)` — return value **never checked**. `m_Buffer` starts as NULL (default ctor). If OOM allocation fails, `m_Buffer` stays NULL.
- Line 73: `stream.Read(m_ExtraData.UseData(), extra_data_size)` — `UseData()` returns NULL. Writing ~4 GB into NULL → NULL dereference / crash (DoS), or if a nothrow build silently allocates a smaller region: heap overflow.

**Group 2 analysis (lines 223–245, extra_length loop):**
- `extra_length -= 4` (line 223), then loop reads `entry_length` per iteration.
- Line 245: `extra_length -= entry_length` — no check that `entry_length <= extra_length`. If `entry_length > extra_length`, unsigned underflow wraps `extra_length` to ~4 GB, causing the loop to keep consuming file bytes (reading past the declared extra data boundary into adjacent box data).

**Group 3 analysis (lines 80–97, `GetSize()`):**
- Line 89: `result = it->GetData()->GetSize()` — missing `+=`. `GetSize()` returns size of last packet only. However, `AP4_MemoryByteStream::WritePartial` dynamically grows its buffer via `Reserve()`, so no overflow occurs in `ToByteStream()`. This is a logic bug, not a memory safety bug — excluded from report.

---

## VULN: Integer underflow in extra_data_size calculation → NULL ptr dereference / heap overflow
- **漏洞类别**: memory-safety
- **函数**: AP4_RtpSampleData::AP4_RtpSampleData()
- **行号**: 70-73
- **CWE**: CWE-191 (Integer Underflow) → CWE-476 (NULL Pointer Dereference) / CWE-122 (Heap-Based Buffer Overflow)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac input.mp4 → AP4_Movie::Parse → AP4_Track with hint track → AP4_HintTrackReader::GetRtpSample() [Ap4HintTrackReader.cpp:143] → `new AP4_RtpSampleData(rtp_data_stream, m_CurrentHintSample.GetSize())` → AP4_RtpSampleData::AP4_RtpSampleData() [Ap4RtpHint.cpp:50] → integer underflow at line 70 → SetDataSize(~4GB) return unchecked → stream.Read(NULL, ~4GB)
- **描述**: `size` 参数来自 hint track 的 `stsz` box，完全由攻击者控制。构造器先读取 `packet_count`（来自文件）并逐包调用 `AP4_RtpPacket(stream)` 解析，每个包至少消耗 12 字节。如果攻击者将 `stsz` 中该 sample 的大小设为极小值（如 4，仅覆盖 packet_count+reserved 头部），而将 `packet_count` 设为 1 以上，则 `extra_data_start - start` 将超过 `size`，导致 `size - (AP4_UI32)(extra_data_start-start)` 发生无符号整数下溢（wraps to ~0xFFFFFFFC ≈ 4 GB）。随后 `m_ExtraData.SetDataSize(~4GB)` 因 OOM 失败，但其返回值被忽略，`m_ExtraData.m_Buffer` 仍为 NULL（默认构造器初始化为 NULL）。最终 `stream.Read(NULL, ~4GB)` 对 NULL 解引用，造成程序崩溃；若编译器/malloc 以 nothrow 方式处理，则写入错误大小的缓冲区导致堆溢出。
- **触发条件**: 构造一个 MP4 文件，其中包含 hint track（如 RTP 传输 track）；将 `stsz` box 中该 sample 的 size 字段设为 4（仅含 packet_count + reserved = 4 字节），同时在 sample 数据中填入 `packet_count = 1`（使解析至少读取 4 + 12 = 16 字节），使得 `extra_data_start - start = 16 > size = 4`，触发下溢。
- **安全影响**: 可靠 DoS（NULL 指针解引用 crash）；在 nothrow 内存分配或特殊运行时环境下，可能升级为堆缓冲区溢出，进一步实现任意代码执行（RCE）。

## VULN: Integer underflow in extra_length loop in AP4_RtpPacket constructor → out-of-bounds stream read
- **漏洞类别**: memory-safety
- **函数**: AP4_RtpPacket::AP4_RtpPacket(AP4_ByteStream&)
- **行号**: 224-245
- **CWE**: CWE-191 (Integer Underflow) → CWE-125 (Out-of-Bounds Read)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac input.mp4 → AP4_HintTrackReader::GetRtpSample() → AP4_RtpSampleData::AP4_RtpSampleData() → AP4_RtpPacket::AP4_RtpPacket(stream) [Ap4RtpHint.cpp:176] → extra_flag 分支，line 224 进入 while 循环 → line 245 `extra_length -= entry_length` 下溢
- **描述**: 在 `AP4_RtpPacket` 构造器解析 extra 数据时，代码先从文件中读取 `extra_length`（AP4_UI32），减去 4 后进入 while 循环。循环每次从文件读取 `entry_length`（AP4_UI32），仅检查 `entry_length < 8`（下界），未检查 `entry_length > extra_length`（超界）。当攻击者构造 `entry_length > extra_length` 时，`extra_length -= entry_length`（line 245）发生无符号整数下溢，`extra_length` 变为一个巨大值（~2^32 - delta），循环条件 `extra_length > 0` 仍为真，导致程序继续从流中读取，越过 extra 数据边界，将相邻 box 的字节作为 entry 头部解析（越界读）；此外，`stream.Seek(cur_pos + entry_length - 8)` 可能将流指针移至任意位置，造成后续解析完全错乱。
- **触发条件**: 构造含 hint track 的 MP4，在 RTP packet 的 extra data 段设置 `extra_length` 为 12（合法最小值），但将第一个 entry 的 `entry_length` 设为 13（> extra_length - 4 = 8），使得 `extra_length -= 13` 从 8 下溢至 0xFFFFFFF3，触发越界读取。
- **安全影响**: 程序越界读取文件（或流）中相邻数据，可能造成信息泄露（暴露不应读取的内存或文件内容），以及后续解析器状态错乱引发的 DoS。

<!-- AUDIT_PROMPT_VERSION: 1 -->
