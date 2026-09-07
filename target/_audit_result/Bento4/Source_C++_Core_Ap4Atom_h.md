I've now completed the multi-pass analysis. Let me compile the final verified findings.

**Summary of analysis groups:**

**Group 1 (Ap4Atom.h + Ap4Atom.cpp lines 465–475):** `AP4_NullTerminatedStringAtom` constructor performs `(AP4_Size)size - AP4_ATOM_HEADER_SIZE` with no lower-bound guard. When `size == 8` (minimum accepted by factory at line 215), `str_size = 0`, then `str[str_size-1] = str[0xFFFFFFFF]` — unsigned 32-bit underflow produces an index ~4 GB past the allocation → OOB write.

**Group 2 (Ap4CttsAtom.cpp lines 78–98):** No entry_count bounds check against atom size. Integer overflow: `entry_count * 8` computed as `AP4_UI32 * int = AP4_UI32`. With entry_count = 0x20000000: `SetItemCount(0x20000000)` allocates 4 GB of entries (succeeds on large-memory machines); `new unsigned char[0x20000000 * 8]` overflows to `new unsigned char[0]`; `stream.Read(buffer, 0)` reads nothing; loop then reads `buffer[i*8]` (heap OOB) for all `i >= 2`, leaking adjacent heap contents into the composition-time-offset table.

**Group 3 (Ap4StszAtom.cpp line 78):** Bounds check `(size-8)/4` should be `(size-20)/4` — allows up to 3 extra entries, causing OOB stream reads (data from the next atom populates the sample-size table). Impact limited to logical corruption; no heap write OOB here.

**Group 4 (stco/co64/trun/stts/elst/sidx):** All lack `entry_count` validation against atom size, leading to unconstrained `SetItemCount` and subsequent `std::bad_alloc` crash (DoS). No integer overflow → under-allocation path because `sizeof(Entry)` equals the buffer's per-element size, so the same count that overflows the buffer also causes the array allocation to throw first. Pure DoS.

**Group 5 (AP4_Array, AP4_DataBuffer, AP4_StcoAtom, AP4_Co64Atom):** Integer underflow in stco/co64 when `size ∈ [12,15]` — produces an unclamped huge `m_EntryCount` → bad_alloc DoS. `AP4_DataBuffer::Reserve` overflow in `m_BufferSize*2+1024` is caught by the `if (new_size < size)` guard. `AppendData` integer wrap requires `existing_size ≈ 4 GB` — not reachable from normal parsing.

---

## VULN: AP4_NullTerminatedStringAtom – Heap OOB Write via Integer Underflow in Index (size == 8)
- **漏洞类别**: memory-safety
- **函数**: `AP4_NullTerminatedStringAtom::AP4_NullTerminatedStringAtom(AP4_Atom::Type, AP4_UI64, AP4_ByteStream&)`
- **行号**: Ap4Atom.cpp:470-473
- **CWE**: CWE-191 (Integer Underflow / Wrap-around) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 7.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: `mp42aac input.mp4` → `AP4_File` → `AP4_DefaultAtomFactory::CreateAtomFromStream` → factory switch `case AP4_ATOM_TYPE_8ID_:` → `new AP4_NullTerminatedStringAtom(type, size_64=8, stream)` → constructor line 470: `AP4_Size str_size = (AP4_Size)8 - 8 = 0`; line 471: `new char[0]`; line 473: `str[0-1]` = `str[0xFFFFFFFF]`
- **描述**: 构造函数计算 `str_size = (AP4_Size)size - AP4_ATOM_HEADER_SIZE`，当 `size == 8`（工厂允许的最小值，满足 `size >= 8` 的检查）时，`str_size = 0`。随后执行 `str[str_size-1] = '\0'`，由于 `str_size` 是无符号 32 位整数，`0 - 1 = 0xFFFFFFFF`，导致写入 `str + 4294967295`（约 4 GB 之外），发生堆越界写入。
- **触发条件**: 在 MP4 文件中构造一个类型为 `8id ` 的 box，将 box size 字段设置为恰好 8（即仅含 8 字节 box 头，无任何 payload），工厂不会拒绝该尺寸。
- **安全影响**: 在 64 位系统上访问未映射内存，进程立即崩溃（可靠的拒绝服务 DoS）；在 32 位系统上地址回绕，'\0' 被写入 `str - 1` 位置（前一堆块的末字节），可用于堆元数据破坏，在条件具备时可升级为远程代码执行（RCE）。

## VULN: AP4_CttsAtom – Integer Overflow in entry_count×8 Produces Zero-Size Buffer → Heap OOB Read
- **漏洞类别**: memory-safety
- **函数**: `AP4_CttsAtom::AP4_CttsAtom(AP4_UI32, AP4_UI08, AP4_UI32, AP4_ByteStream&)`
- **行号**: Ap4CttsAtom.cpp:77-98
- **CWE**: CWE-190 (Integer Overflow) → CWE-125 (Out-of-Bounds Read)
- **CVSS v3.1**: 5.9 (AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: `mp42aac input.mp4` → `AP4_File` → `AP4_StblAtom` 解析 `ctts` box → `AP4_CttsAtom::Create` → `new AP4_CttsAtom(size, ...)` → 构造函数：`stream.ReadUI32(entry_count)` 得到攻击者控制的值 `0x20000000`；`m_Entries.SetItemCount(0x20000000)` 分配 4 GB 条目数组（大内存机器）；`new unsigned char[0x20000000 * 8]` 整数溢出为 0，分配零字节缓冲；循环 `buffer[i*8]` 越界读取堆内存。
- **描述**: `entry_count` 直接来自文件字段，未经任何上界校验。表达式 `new unsigned char[entry_count*8]` 中，`entry_count`（`AP4_UI32`）乘以 `int` 字面量 `8`，结果仍为 `AP4_UI32`，当 `entry_count = 0x20000000` 时，`0x20000000 × 8 = 0x100000000` 回绕为 0，分配零字节缓冲区。`stream.Read(buffer, 0)` 不读入任何数据，随后循环中 `AP4_BytesToUInt32BE(&buffer[i*8])` 对 `i ≥ 2` 时越界读取相邻堆块内容（glibc 零分配通常仅返回 ~16 字节最小块），并将读到的原始堆数据写入 `m_Entries` composition time 偏移表。
- **触发条件**: 在 moov/trak/mdia/minf/stbl 路径下构造一个 `ctts` box，将 `entry_count` 字段设置为 `0x20000000`（536870912），目标系统需具备约 4 GB 以上可用内存（否则 `SetItemCount` 抛出 `bad_alloc` 退化为 DoS）。
- **安全影响**: 越界读取堆内存（信息泄露）；读取的堆内容被用作后续 sample 时间戳偏移，可能在高层逻辑中进一步触发整数溢出或错误偏移计算，最坏情况下配合其他漏洞可升级至 RCE；在内存不足系统上退化为 OOM DoS。

<!-- AUDIT_PROMPT_VERSION: 1 -->
