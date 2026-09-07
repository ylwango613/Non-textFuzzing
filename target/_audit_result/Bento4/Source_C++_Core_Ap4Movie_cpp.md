I have now read all key files in the call chain. Let me compile the findings into the final audit report.

**Batch 1 findings (Ap4Movie.cpp, Ap4Track.cpp, Ap4AtomSampleTable.cpp):** No direct memory safety bugs in these files; they delegate parsing to atom constructors. The attack surface is in the atom parsers called indirectly via `AP4_Movie::AP4_Movie → AP4_Track → AP4_AtomSampleTable → stbl child atoms`.

**Batch 2 findings (Ap4CttsAtom.cpp):** CRITICAL — `entry_count * 8` (lines 79-80) is computed as 32-bit unsigned arithmetic with **no bounds check against the atom size** (unlike stsz/stco which have such checks). When `entry_count ≥ 0x20000000`, the product overflows to a small value → undersized buffer; also `SetItemCount(entry_count)` via `EnsureCapacity` uses `count*sizeof(T)` which also overflows on 32-bit → heap buffer overflow (write) in the placement-new loop.

**Batch 3 findings (Ap4Stz2Atom.cpp):** `(sample_count * m_FieldSize + 7) / 8` at line 90 is 32-bit arithmetic. When the product `sample_count * m_FieldSize` overflows, `table_size` is artificially small. The check at line 91 uses this undersized `table_size`, passes, and then allocates a tiny buffer; the subsequent parsing loop accesses far beyond it. Additionally, `m_Entries.SetItemCount(sample_count)` has the same EnsureCapacity overflow on 32-bit.

**Batch 4 findings (Ap4StcoAtom.cpp):** The underflow check `size - AP4_FULL_ATOM_HEADER_SIZE - 4` when `size < 16` bypasses the bounds check — but the resulting allocation attempt is too large for 32-bit and throws on 64-bit → DoS, not exploitable heap corruption. Not reported.

**Batch 5 findings (Ap4StscAtom.cpp, Ap4SttsAtom.cpp, Ap4DataBuffer.cpp, Mp42Aac.cpp):** No memory safety bugs exploitable through the mp42aac attack path.

## VULN: ctts entry_count Integer Overflow → Heap Buffer Overflow
- **漏洞类别**: memory-safety
- **函数**: AP4_CttsAtom::AP4_CttsAtom()
- **行号**: 78-97 (Ap4CttsAtom.cpp)
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: `mp42aac input.mp4 output.aac` → `AP4_File(input_stream)` → `AP4_File::GetMovie()` → moov box parsing in AP4_AtomFactory → `AP4_CttsAtom::Create()` → `new AP4_CttsAtom(size, version, flags, stream)` [Ap4CttsAtom.cpp:68] → integer overflow at lines 79-80
- **描述**: `entry_count` 直接从 ctts box 的 4 字节字段读取（line 78），无任何与 atom size 对比的上界校验（与 stsz/stco 不同）。line 79 调用 `m_Entries.SetItemCount(entry_count)`，在 AP4_Array::EnsureCapacity 中计算 `count * sizeof(AP4_CttsTableEntry)`（32-bit 乘法：`entry_count(uint32) * 8`），当 entry_count ≥ 0x20000001 时溢出为极小值（如 8），分配不足内存；EnsureCapacity 随后执行 placement-new 循环 `entry_count` 次写入该小缓冲区，造成堆溢出（写）。line 80 的 `new unsigned char[entry_count*8]` 同样经历 32-bit 溢出得到 8 字节缓冲区；line 88 的解析循环执行 `entry_count` 次对该缓冲区的越界读（`buffer[i*8]` for i≥1）。在 64-bit 构建中，EnsureCapacity 的乘法因 size_t 不溢出而尝试分配 >4 GB，以 bad_alloc 的形式造成 DoS；在 32-bit 构建中则触发可控堆内存破坏。
- **触发条件**: 构造一个 MP4 文件，其中 moov/trak/mdia/minf/stbl 包含 ctts box，box 中 entry_count 字段设为 0x20000001（使 entry_count*8 溢出为 8），atom size 字段设为有效的最小 size（≥ AP4_FULL_ATOM_HEADER_SIZE = 12），后跟任意 8 字节数据。
- **安全影响**: 32-bit 构建：攻击者可覆盖堆内存，结合堆布局控制可实现任意代码执行（RCE）。64-bit 构建：进程因分配 4GB+ 失败抛出 bad_alloc 导致 DoS。

## VULN: stz2 sample_count×field_size Integer Overflow → Heap Buffer Over-Read
- **漏洞类别**: memory-safety
- **函数**: AP4_Stz2Atom::AP4_Stz2Atom()
- **行号**: 88-120 (Ap4Stz2Atom.cpp)
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.1 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: `mp42aac input.mp4 output.aac` → `AP4_File` → moov box parsing → `AP4_Stz2Atom::Create()` → `new AP4_Stz2Atom(size, version, flags, stream)` [Ap4Stz2Atom.cpp:71] → integer overflow at line 90
- **描述**: `sample_count`（AP4_Cardinal = uint32，来自文件）与 `m_FieldSize`（AP4_UI08，合法值 4/8/16）相乘发生在 32-bit 无符号运算中（line 90：`unsigned int table_size = (sample_count*m_FieldSize+7)/8`）。当 `sample_count * m_FieldSize ≥ 2^32` 时（如 sample_count=0x20000001, m_FieldSize=16 → 乘积溢出为 0x10），table_size 截断为极小值（如 2），line 91 的合法性检查 `(table_size+8) > size` 因 table_size 虚小而通过，导致 `new unsigned char[table_size]`（line 92）分配远小于所需的缓冲区；line 98-120 的解析循环按原始 sample_count 迭代，访问 `buffer[i*2]`（for i≥1）越界堆内存（over-read）。此外，line 89 `m_Entries.SetItemCount(sample_count)` 在 32-bit 构建中同样导致 EnsureCapacity 内的乘法溢出，产生堆缓冲区溢出（写）。
- **触发条件**: 构造包含 stz2 box 的 MP4 文件：field_size=16，sample_count=0x20000001（确保 sample_count*16 在 uint32 中溢出为 0x10，table_size=2），atom size 字段 ≥ 20（确保 table_size+8=10 不触发早退）。
- **安全影响**: 堆越界读取（读取 table_size 字节缓冲区之外的堆内存），可导致敏感数据泄露或触发进程崩溃（DoS）；32-bit 构建上同时触发堆溢出（写），潜在可实现 RCE。

<!-- AUDIT_PROMPT_VERSION: 1 -->
