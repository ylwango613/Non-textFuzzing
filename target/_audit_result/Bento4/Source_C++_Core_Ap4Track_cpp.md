**Group 1 findings (Ap4Track.cpp direct):** Line 485 has no NULL check on `m_SampleTable` before `m_SampleTable->GetSampleIndexForTimeStamp(...)`, but that function is not in the mp42aac call path.

**Group 2 findings (called via Ap4Track.cpp:242 → AtomSampleTable → box parsers):**

- `AP4_CttsAtom`: no bounds check on `entry_count` before `m_Entries.SetItemCount(entry_count)` and `new unsigned char[entry_count*8]`. On 64-bit: `EnsureCapacity` tries `::operator new(entry_count * sizeof(AP4_CttsTableEntry))` = up to 34 GB → bad_alloc crash (DoS). On 32-bit: `entry_count * 8` overflows to 0 → allocates 0 bytes → subsequent loop does OOB read from `buffer` and OOB write via `m_Entries[i]` (heap corruption).

- `AP4_Stz2Atom`: `unsigned int table_size = (sample_count*m_FieldSize+7)/8` — `sample_count` is AP4_UI32 and `m_FieldSize` is AP4_UI08 (promoted to unsigned int), so the multiplication is 32-bit and overflows to 0 for large `sample_count`. This makes `table_size = 0`, bypassing the guard `(table_size+8) > size`, and allocating 0 bytes. The subsequent element loop then OOB-reads from the 0-byte `buffer`.

- `AP4_StssAtom`: bounds check `(size - AP4_ATOM_HEADER_SIZE - 4)/4` uses 8 instead of 12 for the full-atom header, allowing one extra entry to be parsed from beyond the atom boundary, but the allocation is safe due to the check itself.

- `AP4_StcoAtom`: bounds check `(size - AP4_FULL_ATOM_HEADER_SIZE - 4)/4` underflows when `size < 16` (since Create only guards `size >= AP4_FULL_ATOM_HEADER_SIZE = 12`), making the check ineffective and allowing m_EntryCount to hold values from the stream beyond the atom boundary.

## VULN: AP4_CttsAtom Missing Bounds Check Integer Overflow Heap Corruption
- **漏洞类别**: memory-safety
- **函数**: AP4_CttsAtom::AP4_CttsAtom()
- **行号**: 77-98 (Ap4CttsAtom.cpp)
- **CWE**: CWE-190 (Integer Overflow or Wraparound)
- **CVSS v3.1**: 7.5 (AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_File::AP4_File() → AP4_Movie::AP4_Movie() → AP4_Track::AP4_Track(AP4_TrakAtom&, …) [Ap4Track.cpp:242] → new AP4_AtomSampleTable(stbl, sample_stream) → AP4_CttsAtom::Create() → AP4_CttsAtom::AP4_CttsAtom(size, version, flags, stream)
- **描述**: `ctts` box 的解析构造函数（Ap4CttsAtom.cpp:77-81）直接将文件字段 `entry_count`（AP4_UI32，无任何上界校验）传入 `m_Entries.SetItemCount(entry_count)`，该调用最终执行 `::operator new(entry_count * sizeof(AP4_CttsTableEntry))`（其中 sizeof(AP4_CttsTableEntry) = 8）。在 64 位系统上，当 `entry_count >= 0x20000000`（536M）时，`::operator new` 尝试分配 4 GB 以上内存，抛出 `std::bad_alloc`，进程因未捕获异常而终止（可靠 DoS）。在 32 位系统上，`entry_count * 8` 以 32 位宽度计算发生整数溢出（例如 entry_count=0x20000000 → 乘积=0），`::operator new(0)` 成功返回但实际分配 0 字节，随后 `SetItemCount` 的构造循环及后续 for 循环中 `m_Entries[i]` 的写入全部越界，造成堆缓冲区溢出（潜在 RCE）。
- **触发条件**: 在 MP4 文件中构造一个 `ctts` atom，将其 `entry_count` 字段（偏移 12 字节处的 4 字节大端整数）设为 ≥ 0x20000000（64 位 DoS）或配合整数溢出临界值（32 位堆溢出）；box 的 size 字段可任意填写，无最小数据要求，因为代码对 entry_count 无任何 `size` 相关的上限校验。
- **安全影响**: 64 位系统：可靠的进程崩溃（DoS）；32 位系统：堆元数据及相邻对象被覆盖，攻击者可进一步构造 write-what-where 原语，潜在实现任意代码执行（RCE）。

## VULN: AP4_Stz2Atom Integer Overflow in table_size Bypasses Bounds Check
- **漏洞类别**: memory-safety
- **函数**: AP4_Stz2Atom::AP4_Stz2Atom()
- **行号**: 88-120 (Ap4Stz2Atom.cpp)
- **CWE**: CWE-190 (Integer Overflow or Wraparound)
- **CVSS v3.1**: 7.0 (AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_File::AP4_File() → AP4_Movie::AP4_Movie() → AP4_Track::AP4_Track(AP4_TrakAtom&, …) [Ap4Track.cpp:242] → new AP4_AtomSampleTable(stbl, sample_stream) → AP4_Stz2Atom::Create() → AP4_Stz2Atom::AP4_Stz2Atom(size, version, flags, stream)
- **描述**: 在 `stz2` box 解析函数中，第 90 行计算 `unsigned int table_size = (sample_count * m_FieldSize + 7) / 8`，其中 `sample_count` 为 AP4_UI32，`m_FieldSize` 为 AP4_UI08（提升为 unsigned int），乘法在 32 位宽度内完成。当 `sample_count = 0x10000000` 且 `m_FieldSize = 16` 时，`sample_count * m_FieldSize = 0x100000000 mod 2^32 = 0`，导致 `table_size = 0`。随后的合法性检查 `(table_size + 8) > size` 退化为 `8 > size`，对任何合法 atom（size ≥ 12）均通过，跳过实际的大小校验。代码随即执行 `new unsigned char[0]`（分配 0 字节），然后 `stream.Read(buffer, 0)` 成功返回，进入元素填充循环，在 switch-case 分支中访问 `buffer[i/2]`（对于 m_FieldSize=4 的情形，i 从 0 到 sample_count-1）——`buffer` 仅有 0 字节，所有 `buffer[i/2]` 均为越界读取。写入 `m_Entries[i]` 的部分（若 SetItemCount 在 32 位系统整数溢出下分配了 0 字节）同样越界，构成堆缓冲区越界写入。
- **触发条件**: 构造一个 `stz2` atom，将 `field_size` 字节设为 4、8 或 16，将 `sample_count` 设为使 `sample_count * field_size` 恰好溢出 32 位（如 field_size=16, sample_count=0x10000000）；box size 设为合法最小值（≥ 8）以通过初步校验即可。
- **安全影响**: 堆越界读取导致进程崩溃（DoS）；若 `m_Entries` 的底层分配也因整数溢出而产生（32 位系统），则同时造成堆越界写入，潜在可实现任意代码执行（RCE）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
