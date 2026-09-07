Now I have enough information to write the complete audit report. Let me compile the full findings from my deep analysis.

**Group 1 analysis summary (Ap4CttsAtom.cpp):**
- Line 78: `stream.ReadUI32(entry_count)` — no upper-bound check on entry_count
- Line 79: `m_Entries.SetItemCount(entry_count)` — tries to allocate `entry_count * 8` bytes (via `size_t` → 64-bit, so no overflow here, but 4GB on entry_count=0x20000000 → bad_alloc)
- Line 80: `new unsigned char[entry_count*8]` — here `entry_count * 8` is `AP4_UI32 * int` = **32-bit** result: for entry_count=0x20000000, product=0 → 0-byte buffer
- Lines 88-97: loop reads `buffer[i*8]` for i in [0, entry_count) → OOB read from 0-byte buffer

**Group 2 analysis summary (Ap4Stz2Atom.cpp):**
- Line 82: `stream.ReadUI32(m_SampleCount)` — no check before SetItemCount
- Line 90: `unsigned int table_size = (sample_count*m_FieldSize+7)/8` — **32-bit** multiplication overflows (e.g., m_FieldSize=16, sample_count=0x10000000 → `0x10000000*16=0x100000000` overflows to 0 → table_size=0)
- Line 91: `if ((table_size+8) > size) return;` — wrong check; doesn't account for all 20 consumed header bytes
- Line 92: `new unsigned char[table_size]` — allocated with overflow-reduced size
- Lines 100-118: loop reads `buffer[i/2]` or `buffer[i]` or `buffer[i*2]` for large i → OOB heap reads

**Group 3 analysis summary (Ap4StcoAtom.cpp):**
- Line 78: `(size-AP4_FULL_ATOM_HEADER_SIZE-4)/4` = `(size-16)/4` — integer **underflow** when size ∈ {12,13,14,15} (Create allows size≥12): 12-16=0xFFFFFFFC/4=0x3FFFFFFF
- Line 81: `new AP4_UI32[0x3FFFFFFF]` on 64-bit → `::operator new(0xFFFFFFFC)` ≈ 4 GB → bad_alloc crash

## VULN: AP4_CttsAtom missing bounds check + integer overflow in entry_count*8 → heap OOB read
- **漏洞类别**: memory-safety
- **函数**: AP4_CttsAtom::AP4_CttsAtom()
- **行号**: 77-98 (Ap4CttsAtom.cpp)
- **CWE**: CWE-190 (Integer Overflow or Wraparound), CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac input.mp4 → AP4_File::AP4_File() → AP4_AtomFactory::CreateAtomFromStream() → AP4_CttsAtom::Create(size, stream) → AP4_CttsAtom::AP4_CttsAtom(size, version, flags, stream)
- **描述**: 构造函数从文件流中读取 `entry_count`（AP4_UI32，来自 ctts box data），未做任何上界校验直接调用 `m_Entries.SetItemCount(entry_count)`，然后计算 `new unsigned char[entry_count*8]`。此处 `entry_count`（AP4_UI32）与整数字面量 `8`（int）相乘，结果类型为 **unsigned int（32 位）**，当 `entry_count >= 0x20000000`（268,435,456）时乘积整数溢出为 0，导致分配 0 字节的缓冲区。后续循环 `for (unsigned i=0; i<entry_count; i++) { m_Entries[i].m_SampleCount = AP4_BytesToUInt32BE(&buffer[i*8]); ... }` 以 `entry_count` 次迭代读取 `buffer[i*8]` 和 `buffer[i*8+4]`，全部是对 0 字节缓冲区的越界堆读。在有足够内存（4 GB+）使 SetItemCount 先成功的系统上，越界读取堆上相邻内存，结果写入 m_Entries 进而影响后续 CTS offset 的计算；在内存受限的系统上 SetItemCount 抛出 std::bad_alloc 导致进程崩溃（DoS）。
- **触发条件**: 在 moov/trak/mdia/minf/stbl 中放置一个 ctts box，其 `entry_count` 字段（偏移 16 字节处的 4 字节大端无符号整数）设为 `0x20000000` 或更大值（确保 `entry_count * 8` 的 32 位积溢出）；box 的 declared size 可设为最小合法值（≥12），不需要真实对应的 entry 数据。
- **安全影响**: 在低内存系统（entry_count=0x20000000 时 SetItemCount 尝试申请 4 GB）造成进程崩溃（DoS，CWE-400/CWE-770）；在高内存服务器（4 GB+ 可用堆）上发生堆越界读，将堆上任意数据（包括可能的地址、密钥、其他对象内容）读入 m_Entries CTS 表，构成信息泄露，并可能通过后续错误偏移计算进一步影响控制流。

## VULN: AP4_Stz2Atom integer overflow in (sample_count*m_FieldSize+7)/8 → heap OOB read
- **漏洞类别**: memory-safety
- **函数**: AP4_Stz2Atom::AP4_Stz2Atom()
- **行号**: 88-121 (Ap4Stz2Atom.cpp)
- **CWE**: CWE-190 (Integer Overflow or Wraparound), CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac input.mp4 → AP4_File::AP4_File() → AP4_AtomFactory::CreateAtomFromStream() → AP4_Stz2Atom::Create(size, stream) → AP4_Stz2Atom::AP4_Stz2Atom(size, version, flags, stream)
- **描述**: 构造函数读取 `m_SampleCount`（AP4_UI32，来自 stz2 box 文件字段），无上界检查直接调用 `m_Entries.SetItemCount(sample_count)`，然后计算 `unsigned int table_size = (sample_count * m_FieldSize + 7) / 8`。`sample_count`（AP4_Cardinal = unsigned int，32 位）乘以 `m_FieldSize`（AP4_UI08，8 位，隐式提升到 unsigned int）的积为 **32 位**，当 m_FieldSize=16 且 sample_count=0x10000000（268,435,456）时：`0x10000000 * 16 = 0x100000000`，32 位截断后为 **0**，`table_size = (0+7)/8 = 0`。后续的边界校验 `if ((table_size+8) > size) return;` 仅检查了错误的阈值（缺少已消耗的 20 字节头部偏移，应为 +20 而非 +8），在任何 size≥9 的合法 box 上该校验通过。接下来 `new unsigned char[0]` 分配 0 字节，`stream.Read(buffer, 0)` 读取 0 字节成功；而循环 `for (unsigned int i=0; i<sample_count; i++) { m_Entries[i] = AP4_BytesToUInt16BE(&buffer[i*2]); }` 以 sample_count 次迭代读取 `buffer[i*2]`，全部是对 0 字节缓冲区的越界堆读。由于 m_Entries 被正确分配了 sample_count 个条目，所有越界读取的值被写入 sample size 表，影响后续样本数据的读取偏移与大小。
- **触发条件**: 在 moov/trak/mdia/minf/stbl 中放置一个 stz2 box，将 `field_size`（第 12 字节）设为 16，将 `sample_count`（偏移 13-16 字节处）设为 `0x10000000` 或其他满足 `sample_count * field_size ≥ 2^32` 的值；box size 设为任意 ≥12 的值。mp42aac 使用 stz2 作为 stsz 的替代来源（AtomSampleTable 中 `m_Stz2Atom` 路径），无需同时存在 stsz box。
- **安全影响**: 在内存充足的服务器（~1 GB 可用堆）上，m_Entries 正确分配，越界读取从 0 字节 buffer 附近的堆内存获取任意值写入 sample size 表，构成堆信息泄露；错误的 sample size 值被后续 ReadData/SetDataSize 使用，可能触发超大内存分配（DoS）或错误文件偏移访问。在内存不足时 SetItemCount 抛出 bad_alloc，进程崩溃（DoS）。

## VULN: AP4_StcoAtom integer underflow in bounds check causes giant heap allocation crash
- **漏洞类别**: memory-safety
- **函数**: AP4_StcoAtom::AP4_StcoAtom()
- **行号**: 77-92 (Ap4StcoAtom.cpp)
- **CWE**: CWE-191 (Integer Underflow), CWE-770 (Allocation of Resources Without Limits or Throttling)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac input.mp4 → AP4_File::AP4_File() → AP4_AtomFactory::CreateAtomFromStream() → AP4_StcoAtom::Create(size, stream) → AP4_StcoAtom::AP4_StcoAtom(size, version, flags, stream)
- **描述**: 构造函数的边界校验表达式 `(size - AP4_FULL_ATOM_HEADER_SIZE - 4) / 4`（即 `(size - 16) / 4`）在 `size ∈ {12, 13, 14, 15}` 时发生无符号整数下溢：例如 `size=12` 时 `12-16 = 0xFFFFFFFC`（uint32），除以 4 得 `0x3FFFFFFF`。Create 函数仅检查 `size < AP4_FULL_ATOM_HEADER_SIZE（=12）` 即允许 `size=12`，因此下溢可达。当文件字段 `m_EntryCount` 值大于 0 时，比较 `m_EntryCount > 0x3FFFFFFF` 失败（若 m_EntryCount ≤ 0x3FFFFFFF），导致 m_EntryCount 被钳制到 0x3FFFFFFF，随后 `new AP4_UI32[0x3FFFFFFF]` 在 64 位系统上请求约 4 GB 内存，抛出 std::bad_alloc 使进程崩溃。
- **触发条件**: 构造一个 stco box（chunk offset table），将 box 的 `size` 字段声明为 12（或 13–15），并将紧随其后的 `entry_count` 字段（实际在 size=12 时读自该 box 边界外的下一字节）设为任意非零值；mp42aac 在解析 audio track 的 stbl 时会命中此 box。
- **安全影响**: 进程因 std::bad_alloc 异常未捕获而崩溃，造成拒绝服务（DoS）；在以库形式集成的场景中，若异常被捕获，则 m_EntryCount 为极大值导致后续行为不可预期。

<!-- AUDIT_PROMPT_VERSION: 1 -->
