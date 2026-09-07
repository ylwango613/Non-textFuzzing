I have completed thorough analysis of all major atom parsers. Let me now compile the final vulnerability report.

**Summary of findings across all parsers reviewed:**

- **stco, co64, stsc, stss**: Have explicit `entry_count > (size-header)/stride` bounds checks — safe
- **ctts**: NO bounds check on `entry_count`; `entry_count*8` can integer-overflow; `SetItemCount` return unchecked
- **stz2**: NO bounds check on `sample_count`; `(sample_count*m_FieldSize+7)/8` can overflow and bypass the size check at line 91
- **stts**: Uses `Append` in a loop (no static buffer), DoS-level only
- **elst**: Uses `EnsureCapacity` + `Append`, dynamic sizing, safe from overflow
- **trun**: `SetItemCount(sample_count)` return unchecked; NULL dereference path when allocation fails without exceptions
- **saio**: Has `remains < entry_count * (version==0?4:8)` overflow risk but not in main mp42aac path

---

## VULN: AP4_CttsAtom integer overflow in entry_count*8 leads to heap corruption
- **漏洞类别**: memory-safety
- **函数**: AP4_CttsAtom::AP4_CttsAtom(AP4_UI32, AP4_UI08, AP4_UI32, AP4_ByteStream&)
- **行号**: 77-97
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_File(input) → AP4_AtomFactory → AP4_CttsAtom::Create() → new AP4_CttsAtom(size, version, flags, stream)
- **描述**: `Ap4CttsAtom.cpp` 第 79-97 行，ctts box 解析时直接使用文件中读取的 `entry_count`（AP4_UI32），无任何上界校验（对比 stco/stsc 均有 `entry_count > (size-header)/stride` 类校验）。第 79 行 `m_Entries.SetItemCount(entry_count)` 返回值未检查：在 32 位平台或 `-fno-exceptions` 构建中，EnsureCapacity 内部 `count * sizeof(AP4_CttsTableEntry)` = `entry_count * 8` 在 32 位运算下溢出为 0，`::operator new(0)` 返回非 NULL 的极小分配，SetItemCount 成功返回但 m_Items 指向极小堆块；随后第 80 行 `new unsigned char[entry_count*8]`（AP4_UI32 * int → 32 位截断）同样溢出为 0，分配 0 字节缓冲区；第 81 行 `stream.Read(buffer, 0)` 读取 0 字节成功；第 88-96 行 for 循环对 `buffer[i*8]` 进行堆缓冲区越界读（i≥1 时立即越界），并对 `m_Entries[i]` 进行越界写（m_Items 指向极小分配）。在 64 位有异常的标准构建中，EnsureCapacity 用 size_t 运算（0x20000000×8=4GB），OOM 抛出 bad_alloc → DoS。
- **触发条件**: MP4 文件包含 ctts box，其 entry_count 字段设为 ≥0x20000000（32 位构建）或任意大值（64 位 DoS）；box 实际数据可以极短（body 仅含 entry_count 字段本身，buffer 溢出后 stream.Read(0字节) 成功）。
- **安全影响**: 32 位或 `-fno-exceptions` 构建：堆缓冲区溢出（OOB write 覆盖相邻堆元数据/对象），潜在 RCE；64 位标准构建：未处理的 std::bad_alloc 导致进程崩溃（DoS）。

## VULN: AP4_Stz2Atom integer overflow in table_size bypasses bounds check leading to heap over-read
- **漏洞类别**: memory-safety
- **函数**: AP4_Stz2Atom::AP4_Stz2Atom(AP4_UI32, AP4_UI08, AP4_UI32, AP4_ByteStream&)
- **行号**: 88-121
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-125 (Out-of-bounds Read) / CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_File(input) → AP4_AtomFactory → AP4_Stz2Atom::Create() → new AP4_Stz2Atom(size, version, flags, stream)
- **描述**: `Ap4Stz2Atom.cpp` 第 82 行读取 `m_SampleCount`（AP4_UI32，来自文件），无任何上界校验。第 89 行 `m_Entries.SetItemCount(sample_count)` 返回值未检查（与 ctts 同样模式）。第 90 行 `unsigned int table_size = (sample_count * m_FieldSize + 7) / 8`：当 `m_FieldSize=4` 且 `sample_count ≥ 0x40000000` 时，`sample_count * 4` 在 32 位 unsigned int 算术下溢出为 0，`table_size = (0+7)/8 = 0`。第 91 行边界检查 `(table_size+8) > size` 变为 `8 > size`，对任何 size≥8 的 box 均通过，完全绕过！之后 `new unsigned char[0]` 分配 0 字节缓冲区，`stream.Read(buffer, 0)` 读 0 字节成功，for 循环对 `buffer[i/2]`（field_size=4 分支）或 `buffer[i]`（field_size=8）或 `buffer[i*2]`（field_size=16）进行越界读（i≥1 立即越界），并对 `m_Entries[i]` 越界写（分配不足时）。
- **触发条件**: MP4 文件包含 stz2 box，field_size=4，sample_count ≥ 0x40000000；box body 只需包含头字段，无需实际 sample 数据（stream.Read(0) 成功）。
- **安全影响**: 32 位或 `-fno-exceptions` 构建：堆缓冲区越界读（信息泄露）及越界写（堆元数据/对象破坏），潜在 RCE；64 位标准构建：OOM bad_alloc 或堆越界读导致崩溃（DoS）。

## VULN: AP4_TrunAtom unchecked SetItemCount failure leads to null pointer dereference in sample loop
- **漏洞类别**: memory-safety
- **函数**: AP4_TrunAtom::AP4_TrunAtom(AP4_UI32, AP4_UI08, AP4_UI32, AP4_ByteStream&)
- **行号**: 127-151
- **CWE**: CWE-252 (Unchecked Return Value) → CWE-476 (NULL Pointer Dereference)
- **CVSS v3.1**: 5.5 (AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_File(input) → AP4_AtomFactory（解析 moof/traf/trun box）→ AP4_TrunAtom::Create() → new AP4_TrunAtom(size, version, flags, stream)
- **描述**: `Ap4TrunAtom.cpp` 第 127 行 `m_Entries.SetItemCount(sample_count)` 返回值未检查。若 `sample_count` 超大（攻击者在 trun box 中设置大值），EnsureCapacity 内 `::operator new` 失败：在有异常构建中抛出 bad_alloc（DoS）；在 `-fno-exceptions` 构建中返回 NULL，EnsureCapacity 返回 `AP4_ERROR_OUT_OF_MEMORY`，SetItemCount 返回错误（未检查），`m_Items` 仍为 NULL。随后 for 循环第 128-151 行直接访问 `m_Entries[i]`（即 `m_Items[i]`），m_Items 为 NULL → 空指针解引用 → 进程崩溃。在 32 位平台上，`sample_count * sizeof(Entry)`（sizeof(Entry)=16）也可能整数溢出为 0，产生微小分配后 for 循环越界写入（堆破坏）。
- **触发条件**: MP4 文件包含 moof → traf → trun box 子树，trun 的 sample_count 字段设为极大值（如 0x10000000）；box size 可以极小（系统尝试分配大量内存即可触发）。
- **安全影响**: 64 位标准构建：未处理的 bad_alloc 或 NULL 解引用导致进程崩溃（DoS）；32 位构建：潜在堆破坏，可能升级为 RCE。

<!-- AUDIT_PROMPT_VERSION: 1 -->
