I now have full context on both vulnerabilities. Let me write the final security audit report.

## VULN: AP4_CttsAtom Integer Overflow → Heap Buffer Over-Read
- **漏洞类别**: memory-safety
- **函数**: AP4_CttsAtom::AP4_CttsAtom()
- **行号**: 77-97 (Ap4CttsAtom.cpp)
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac(main) → AP4_File::AP4_File(stream) → AP4_AtomFactory::CreateAtomFromStream() → AP4_CttsAtom::Create(size_32, stream) → AP4_CttsAtom::AP4_CttsAtom(size, version, flags, stream)
- **描述**: ctts atom 构造函数在分配读取缓冲区之前未对 entry_count 进行边界校验。第 80 行 `new unsigned char[entry_count*8]` 中，entry_count 为 AP4_UI32，与整数字面量 8 相乘时按 32-bit 无符号运算：当 entry_count ≥ 0x20000000 时，乘积模 2^32 后变为极小值（如 entry_count=0x20000001 时乘积为 8），导致缓冲区严重欠分配。而第 79 行 `m_Entries.SetItemCount(entry_count)` 中 EnsureCapacity 使用 64-bit 乘法（uint32 × size_t），正确计算出 ~4GB 容量并尝试分配。随后第 88-97 行循环 `for (unsigned i=0; i<entry_count; i++)` 中，`buffer[i*8]` 在 i=1 时即访问越界地址（buffer 仅 8 字节，但 i=1 时 i*8=8 超出范围），造成堆缓冲区越界读取，读到的相邻堆内存值被写入 m_Entries[i]。与 AP4_StscAtom/AP4_StcoAtom 等兄弟 atom 均有 `if (count > (size-header)/element_size)` 保护不同，AP4_CttsAtom 完全没有此检查。
- **触发条件**: 构造一个 ctts box（moov/trak/mdia/minf/stbl/ctts），其 entry_count 字段设为 0x20000001（或任意满足 entry_count*8 在 32-bit 下溢出的值，如 0x20000000、0x40000000 等），而 box size 仅填写实际有效数据的大小（如 24 字节，含 1 条真实 entry）。整个 MP4 文件可以很小（< 1KB）。
- **安全影响**: 最直接影响为 DoS：EnsureCapacity 尝试分配 ~4GB 虚拟内存，在具有 memory overcommit 的 Linux 上分配"成功"后 SetItemCount 构造循环触碰 4GB 页面导致 OOM Killer 杀掉进程；在无 overcommit 系统上 std::bad_alloc 异常未被捕获直接 abort。在内存资源充足的高内存系统上，堆越界读取会泄露相邻堆块内容（可能包含指针、解密密钥等敏感数据），在特定堆布局下可能被利用为信息泄露或内存破坏原语。

## VULN: AP4_Stz2Atom Integer Overflow Bypasses Size Check → Heap Buffer Over-Read
- **漏洞类别**: memory-safety
- **函数**: AP4_Stz2Atom::AP4_Stz2Atom()
- **行号**: 88-121 (Ap4Stz2Atom.cpp)
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac(main) → AP4_File::AP4_File(stream) → AP4_AtomFactory::CreateAtomFromStream() → AP4_Stz2Atom::Create(size_32, stream) → AP4_Stz2Atom::AP4_Stz2Atom(size, version, flags, stream)
- **描述**: stz2 atom 构造函数第 90 行 `unsigned int table_size = (sample_count*m_FieldSize+7)/8` 中，sample_count 为 AP4_UI32，m_FieldSize 为 AP4_UI08（经整数提升为 int，再经常规算术转换变为 unsigned int），两者相乘为 32-bit 无符号运算，大 sample_count 下溢出：当 m_FieldSize=4 且 sample_count=0x40000001 时，`sample_count*4 = 0x100000004` mod 2^32 = 4，table_size = (4+7)/8 = 1。此极小的 table_size 使得第 91 行的保护检查 `if ((table_size+8) > size) return;`（1+8=9 ≤ 12，不触发）形同虚设，随后 `new unsigned char[1]` 仅分配 1 字节缓冲区。第 100-106 行 case 4 分支循环中，i=2 时 `buffer[i/2] = buffer[1]` 越界访问（buffer 只有 index 0 合法）；case 8 时 i=1 即越界；case 16 时 i=1 的 `buffer[i*2]=buffer[2]` 越界。同样，第 89 行 `m_Entries.SetItemCount(sample_count)` 使用 64-bit 乘法尝试分配 ~4GB（m_FieldSize=8时）或 ~16GB（m_FieldSize=4时）。
- **触发条件**: 构造一个 stz2 box（moov/trak/mdia/minf/stbl/stz2），field_size 字段设为 4、8 或 16（合法值），sample_count 设为使 `sample_count * field_size` 在 32-bit 下溢出的值（如 field_size=4 时 sample_count=0x40000001），box size 取合法小值（≥12 即可）。整个 MP4 文件可以很小（< 1KB）。
- **安全影响**: 与 ctts 漏洞相同：主要影响为 DoS（~4-16GB 分配尝试，OOM 或 bad_alloc 致进程崩溃）；在内存充足的系统上退化为堆越界读取，可能泄露相邻堆内存内容或被用于更复杂的内存破坏利用链。

<!-- AUDIT_PROMPT_VERSION: 1 -->
