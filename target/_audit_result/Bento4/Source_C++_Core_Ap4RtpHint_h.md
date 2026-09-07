Now I have sufficient context. Let me compile the analysis.

**Analysis of `Ap4RtpHint.cpp` — Group 1 (lines 1–75): `AP4_RtpSampleData` constructor**

Line 70: `AP4_Size extra_data_size = size - (AP4_UI32)(extra_data_start-start);`
- `size` = sample size from stsz box (file-controlled UI32)
- `extra_data_start - start` = bytes consumed parsing packets (also file-controlled, no upper bound check)
- There is NO guard that `(extra_data_start - start) <= size`
- If crafted packets consume more bytes than `size`, unsigned underflow wraps `extra_data_size` to ~4 GB
- Line 72-73: `m_ExtraData.SetDataSize(huge)` → `ReallocateBuffer(huge)` → `new AP4_Byte[huge]` (no nothrow) → `std::bad_alloc` thrown uncaught → process crash (DoS)

**Analysis of `Ap4RtpHint.cpp` — Group 2 (lines 210–255): `AP4_RtpPacket` constructor extra-data loop**

Line 245: `extra_length -= entry_length;`
- Both `extra_length` and `entry_length` are `AP4_UI32` (unsigned)
- `entry_length` is checked `>= 8` but there is NO check that `entry_length <= extra_length`
- If an attacker sets `entry_length > extra_length`, unsigned subtraction wraps `extra_length` to ~4 billion
- Loop condition `extra_length > 0` stays true for billions of iterations → CPU DoS
- Each iteration calls `stream.Tell`, `stream.Seek`, `stream.ReadUI32` on stale/EOF stream

**Analysis of `AP4_RtpSampleData::GetSize()` (lines 87–89) + `ToByteStream()` (line 109)**

`result = it->GetData()->GetSize()` — missing `+=`, only last packet size accumulated. But `AP4_MemoryByteStream(size)` with internal buffer is growable (Reserve succeeds for local buffers), so writes beyond `size` just trigger realloc. No heap overflow results. Logic bug only — not reportable per task scope.

**Analysis: `AP4_ImmediateRtpConstructor` (lines 456–470)**

`data_size` is UI08 (max 255), buffer correctly allocated to `data_size`, seek restores stream position. No heap safety issue.

**Call chain confirmation:** `AP4_HintTrackReader::GetRtpSample` (Ap4HintTrackReader.cpp:143) → `new AP4_RtpSampleData(stream, m_CurrentHintSample.GetSize())` → vulnerability sites. The `GetSize()` return value comes from the `stsz` box (file-controlled).

## VULN: Integer Underflow in AP4_RtpSampleData Constructor Leads to OOM Crash
- **漏洞类别**: memory-safety
- **函数**: AP4_RtpSampleData::AP4_RtpSampleData(AP4_ByteStream&, AP4_UI32)
- **行号**: 70-73
- **CWE**: CWE-191 (Integer Underflow) / CWE-789 (Uncontrolled Memory Allocation)
- **CVSS v3.1**: 5.5 (AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: 攻击者传入含 hint track 的恶意 MP4 → AP4_HintTrackReader::GetRtpSample() (Ap4HintTrackReader.cpp:143) → new AP4_RtpSampleData(stream, m_CurrentHintSample.GetSize()) → AP4_RtpSampleData::AP4_RtpSampleData(Ap4RtpHint.cpp:70) → m_ExtraData.SetDataSize(underflowed_size) → AP4_DataBuffer::ReallocateBuffer → new AP4_Byte[~4GB] → std::bad_alloc thrown uncaught
- **描述**: 在 `AP4_RtpSampleData` 构造函数的第 70 行，通过 `size - (AP4_UI32)(extra_data_start - start)` 计算 extra data 大小。`size` 来自文件中 hint track sample 的 stsz box（攻击者可控 UI32），`extra_data_start - start` 为解析数据包后的流偏移差值（同样受攻击者控制），两者均无上界校验。若精心构造的数据包结构使实际消耗字节数超过 `size`，该无符号减法下溢产生约 4GB 的 `extra_data_size`；该值随即传入 `m_ExtraData.SetDataSize()` → `ReallocateBuffer()` → 标准 `new AP4_Byte[~4GB]`（非 nothrow 形式），内存分配失败则抛出未被捕获的 `std::bad_alloc`，导致进程崩溃。
- **触发条件**: 构造一个含 hint track 的 MP4 文件，将 hint sample 的 `size` 字段（stsz）设为较小值（如 8），同时在 sample data 中设置足量的 `packet_count`（UI16）和每个 `AP4_RtpPacket` 中的 `constructor_count`（UI16）使实际解析消耗字节数超过 `size`；之后 extra_data_size 下溢为巨大值，触发 OOM。
- **安全影响**: 进程因未捕获 `std::bad_alloc` 异常而终止，造成拒绝服务（DoS）；在 Linux 内存过度提交（overcommit）模式下分配可能"成功"，后续 stream.Read 将大量读取文件数据至错误大小的缓冲区，进一步扩大影响。

## VULN: Unsigned Integer Underflow in AP4_RtpPacket Extra-Data Loop Causes CPU DoS
- **漏洞类别**: memory-safety
- **函数**: AP4_RtpPacket::AP4_RtpPacket(AP4_ByteStream&)
- **行号**: 224-246
- **CWE**: CWE-191 (Integer Underflow) / CWE-835 (Loop with Unreachable Exit Condition)
- **CVSS v3.1**: 4.7 (AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: 攻击者传入含 hint track 的恶意 MP4 → AP4_HintTrackReader::GetRtpSample() → AP4_RtpSampleData::AP4_RtpSampleData() → new AP4_RtpPacket(stream) (Ap4RtpHint.cpp:64) → AP4_RtpPacket::AP4_RtpPacket(AP4_ByteStream&) → extra_flag=1 分支 → while(extra_length>0) 循环第 245 行 extra_length -= entry_length 下溢
- **描述**: 在 `AP4_RtpPacket` 的流构造函数中（第 214–247 行），当 `extra_flag` 为真时读取 `extra_length`（UI32，来自文件），减去 4 后进入 while 循环。循环内从流读取 `entry_length`（UI32，来自文件）后仅检查 `entry_length < 8` 就继续执行，但未检查 `entry_length <= extra_length`。第 245 行 `extra_length -= entry_length` 为无符号减法：若攻击者令 `entry_length > extra_length`，则下溢产生接近 2^32 的巨大值，使 `extra_length > 0` 条件对数十亿次迭代均为真。每次迭代调用 stream.Tell/Seek/ReadUI32，产生极高 CPU 占用，导致拒绝服务。
- **触发条件**: 在 hint track sample 的 `AP4_RtpPacket` header 中设置 extra_flag=1，`extra_length` 设为 12（合法最小值，减 4 后余 8），第一个 entry 的 `entry_length` 设为大于 8 的值（如 1000），使 `8 - 1000` 无符号下溢至 0xFFFFFC18，循环继续数十亿次。
- **安全影响**: 进程 CPU 占用被锁定至接近 100%（DoS），在大多数实现下最终因流 EOF 后读取失败 entry_length 为 0 而退出，但在可重入场景（服务端批量处理 MP4）下可造成持续拒绝服务。

<!-- AUDIT_PROMPT_VERSION: 1 -->
