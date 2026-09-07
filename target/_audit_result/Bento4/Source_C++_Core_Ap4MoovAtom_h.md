I now have all the information needed for a complete audit. Let me summarize the findings:

**Batch 1 analysis (Ap4MoovAtom.h + .cpp):** The moov atom itself is a thin container atom — its constructor, `OnChildAdded`, `OnChildRemoved`, and `AdjustChunkOffsets` are all clean. The vulnerabilities lie in the atoms parsed as moov's grandchildren.

**Batch 2 analysis (child atom parsers stco, stsz, stsc, stts, ctts, stss, stz2):**

- **stco, stsc, stts, stss, stsz**: all have explicit `entry_count ≤ (size - header - field)/element_bytes` bounds checks before allocations.
- **ctts (Ap4CttsAtom.cpp:77-98)**: `entry_count` is read from file and passed **directly** to `m_Entries.SetItemCount(entry_count)` and `new unsigned char[entry_count*8]` with NO bounds check. On 32-bit: `EnsureCapacity(count)` computes `count * sizeof(T)` as 32-bit `size_t`; for `entry_count = 0x20000001`, `0x20000001 * 8 = 0x100000008` wraps to `8`, allocating an 8-byte block that is then treated as `0x20000001` entries — classic integer overflow → heap buffer overflow.
- **stz2 (Ap4Stz2Atom.cpp:88-96)**: `unsigned int table_size = (sample_count * m_FieldSize + 7) / 8` where both operands are 32-bit; for `sample_count = 0x10000000, m_FieldSize = 16`, the product wraps to 0, making `table_size = 0`, bypassing the size guard `(table_size + 8) > size`. A 0-byte buffer is then allocated and the loop indexes `buffer[i*2]` for 0x10000000 iterations — heap OOB read.
- **stco (Ap4StcoAtom.cpp:78-79)**: The bounds-check expression `(size - AP4_FULL_ATOM_HEADER_SIZE - 4)/4` underflows when `size ∈ [12,15]`, wrapping to `0x3FFFFFFF`, which allows the file to supply any `m_EntryCount ≤ 0x3FFFFFFF` (read from outside the box boundary) leading to a ~4 GB allocation → OOM DoS.

## VULN: ctts atom missing entry_count bounds check — integer overflow → heap overflow
- **漏洞类别**: memory-safety
- **函数**: AP4_CttsAtom::AP4_CttsAtom()
- **行号**: 77-98
- **CWE**: CWE-190 (Integer Overflow or Wraparound) leading to CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_File::AP4_File(stream) → AP4_AtomFactory::CreateAtomFromStream() → AP4_MoovAtom constructor → AP4_ContainerAtom::ReadChildren() (moov) → ReadChildren (trak→mdia→minf→stbl) → AP4_CttsAtom::Create() → AP4_CttsAtom::AP4_CttsAtom(size, version, flags, stream)
- **描述**: `AP4_CttsAtom::AP4_CttsAtom()` reads `entry_count` (AP4_UI32) from the file at line 78 and immediately passes it to `m_Entries.SetItemCount(entry_count)` (line 79) and `new unsigned char[entry_count*8]` (line 80) with **no** bounds check against the box size field — unlike every sibling atom (stco, stsc, stts, stss, stsz) which all enforce `entry_count ≤ (size − header − field)/element_size`. On 32-bit targets, `AP4_Array<T>::EnsureCapacity(count)` computes the allocation size as `count * sizeof(T)` in 32-bit `size_t` arithmetic: `0x20000001 × 8 = 0x100000008` wraps to `8`, so `::operator new(8)` succeeds. The subsequent `SetItemCount` loop then constructs `0x20000001` AP4_CttsTableEntry objects (8 bytes each = 4 GB of heap writes) into the 8-byte allocation, corrupting the heap. On 64-bit targets the 64-bit arithmetic prevents the wrap but instead triggers an unhandled `std::bad_alloc` (reliable crash / DoS).
- **触发条件**: 在 MP4 文件的 moov→trak→mdia→minf→stbl 层级中包含一个 ctts box，box 体积可以很小（如 20 字节），但其中 entry_count 字段设为 ≥ 0x20000001（32 位堆溢出）或任意大值（64 位 OOM）。无需其他条件。
- **安全影响**: 32 位目标上可实现堆内存完全破坏，进而利用标准堆漏洞技术实现任意代码执行（RCE）。64 位目标上可靠触发程序崩溃（DoS）。

## VULN: stz2 atom integer overflow in table_size bypasses size guard — heap OOB read
- **漏洞类别**: memory-safety
- **函数**: AP4_Stz2Atom::AP4_Stz2Atom()
- **行号**: 88-119
- **CWE**: CWE-190 (Integer Overflow or Wraparound) leading to CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_File::AP4_File(stream) → AP4_AtomFactory::CreateAtomFromStream() → AP4_MoovAtom → AP4_ContainerAtom::ReadChildren() (moov→trak→mdia→minf→stbl) → AP4_Stz2Atom::Create() → AP4_Stz2Atom::AP4_Stz2Atom(size, version, flags, stream)
- **描述**: 在 `AP4_Stz2Atom` 构造函数中，`m_SampleCount`（AP4_UI32，来自文件）和 `m_FieldSize`（AP4_UI08，值为 4/8/16）相乘用于计算 `table_size`：`unsigned int table_size = (sample_count * m_FieldSize + 7) / 8`（第 90 行）。`sample_count × m_FieldSize` 的结果类型为 AP4_UI32（32 位无符号），当 `sample_count = 0x10000000`、`m_FieldSize = 16` 时，`0x10000000 × 16 = 0x100000000` 溢出回绕为 0，使 `table_size = 0`。后续安全检查 `(table_size + 8) > size`（第 91 行）因 table_size = 0 而无法拦截，程序继续执行 `new unsigned char[0]`（合法 0 字节分配），然后在循环中用 `buffer[i*2]`（`i` 最大达 `0x0FFFFFFF`）读取该 0 字节缓冲区之外的堆内存，发生大范围越界读。此前调用的 `m_Entries.SetItemCount(0x10000000)` 会在 64 位系统上尝试分配 1 GB（成功则后续触发 OOB read；失败则 OOM DoS）。
- **触发条件**: 在 MP4 文件的 stbl box 中包含一个 stz2 box，其中 `field_size = 16`，`sample_count ≥ 0x10000000`（使 `sample_count × 16` 溢出为 0）。在有 1 GB 以上可用内存的 64 位系统上触发越界读；内存受限时触发 OOM DoS。
- **安全影响**: 堆越界读取（heap OOB read）可泄露相邻堆内存数据（ASLR 绕过辅助信息、潜在敏感内容），同时稳定触发程序崩溃（DoS）。

## VULN: stco bounds-check integer underflow for small box sizes — OOM DoS via out-of-box entry_count
- **漏洞类别**: memory-safety
- **函数**: AP4_StcoAtom::AP4_StcoAtom()
- **行号**: 77-92
- **CWE**: CWE-191 (Integer Underflow) leading to CWE-400 (Uncontrolled Resource Consumption)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_File::AP4_File(stream) → AP4_AtomFactory::CreateAtomFromStream() → moov→trak→mdia→minf→stbl → AP4_StcoAtom::Create() → AP4_StcoAtom::AP4_StcoAtom(size, version, flags, stream)
- **描述**: `AP4_StcoAtom` 构造函数使用 `(size - AP4_FULL_ATOM_HEADER_SIZE - 4) / 4` 来上限 `m_EntryCount`（第 78-80 行）。当 `size ∈ [12, 15]`（最小合法值由 `Create()` 的 `size < AP4_FULL_ATOM_HEADER_SIZE` 检查保证 size ≥ 12）时，减法 `size - 12 - 4` 作为 AP4_UI32 无符号运算回绕为大值（如 size=12 → 0xFFFFFFFC），除以 4 得 0x3FFFFFFF，使安全检查实际允许 m_EntryCount 达 10 亿。此时 `m_EntryCount` 由在 box 边界之外读取到的 4 字节（下一个 atom 的数据）决定，攻击者可完全控制该值，从而触发 `new AP4_UI32[m_EntryCount]` 和 `new unsigned char[m_EntryCount*4]` 尝试分配 ~4 GB 内存，导致未处理的 `std::bad_alloc` 异常崩溃进程。
- **触发条件**: 在 stbl box 中包含一个 size 字段恰好为 12-15 的 stco box，并在其后紧接大整数值（如 0x3FFFFFFF），使越界读取到的 entry_count 超出正常范围。
- **安全影响**: 稳定触发进程崩溃（DoS）；无法利用为堆破坏（两次分配大小均无 32 位溢出，仅为 OOM）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
