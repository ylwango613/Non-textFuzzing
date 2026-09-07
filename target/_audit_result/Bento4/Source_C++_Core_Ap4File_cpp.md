Now I have enough context to write the final report. Let me do a final check on the Stz2Atom to confirm the integer overflow scenario.

**Batch 1 findings (ctts, line 77–98):** `entry_count` from file passed to `SetItemCount` and `new unsigned char[entry_count*8]` with no bounds check against `size`. On 32-bit: `entry_count=0x20000001` → `entry_count*8 = 8` (32-bit wrap) → 8-byte allocation, then loop runs 536M times OOB. On 64-bit: bad_alloc → crash.

**Batch 2 findings (sbgp, line 87):** Bounds check `remains < entry_count*8` where `entry_count*8` overflows to 0 → check always passes → huge `SetItemCount` → OOM/crash.

**Batch 3 findings (stz2, lines 89–92):** `m_Entries.SetItemCount(sample_count)` before table_size computation; `table_size=(sample_count*m_FieldSize+7)/8` can wrap to 0 or a tiny value; under-allocated buffer, then loop accesses `buffer[i*2]` for huge i.

## VULN: AP4_CttsAtom – Missing entry_count bounds check enables integer-overflow heap-buffer-overflow
- **漏洞类别**: memory-safety
- **函数**: AP4_CttsAtom::AP4_CttsAtom()
- **行号**: 77-98
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → new AP4_File(*input) → AP4_File::ParseStream() → AP4_AtomFactory::CreateAtomFromStream() → AP4_CttsAtom::Create(size_32, stream) → new AP4_CttsAtom(size, version, flags, stream)
- **描述**: AP4_CttsAtom 构造函数从文件直接读取 entry_count（AP4_UI32），既不与 size 参数作比较，也不做任何上界检查（对比 AP4_StcoAtom/AP4_StszAtom 均有 `m_EntryCount > (size-header-4)/N` 的截断）。随后计算 `entry_count * 8` 时两处（SetItemCount 传入 EnsureCapacity 的 `count * sizeof(T)` 在 32-bit 上、以及 `new unsigned char[entry_count*8]` 的乘法）均为 32-bit AP4_UI32 算术，当 `entry_count = 0x20000001` 时乘积溢出为 8；EnsureCapacity 仅分配 8 字节但将 m_AllocatedCount 设为 0x20000001，随后 SetItemCount 的构造循环从 i=1 起写入 m_Items[1] 即越界；buffer 同样仅分配 8 字节，后续循环在 i≥1 时 `buffer[i*8]`（OOB 读）和 `m_Entries[i]`（OOB 写）均越界。在 64-bit 系统上 sizeof(T) 的 64-bit 算术使 EnsureCapacity 申请约 4 GB，抛出 std::bad_alloc 导致进程崩溃（DoS）。
- **触发条件**: 在 MP4 文件的 moov→trak→mdia→minf→stbl 容器中嵌入一个 ctts box，box size 字段设为任意合法值（如 24），但 entry_count 字段设为 0x20000001（或任何使 `entry_count*8` 32-bit 溢出的值），box 内包含至少 8 字节填充数据。
- **安全影响**: 32-bit 构建上：受控的堆缓冲区溢出写，可通过堆利用技术实现任意代码执行（RCE）；64-bit 构建上：进程因 std::bad_alloc 或 null pointer dereference 崩溃（DoS）。

## VULN: AP4_SbgpAtom – Integer overflow in bounds check allows entry_count bypass leading to heap corruption
- **漏洞类别**: memory-safety
- **函数**: AP4_SbgpAtom::AP4_SbgpAtom()
- **行号**: 83-96
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → new AP4_File(*input) → AP4_File::ParseStream() → AP4_AtomFactory::CreateAtomFromStream() → AP4_SbgpAtom::Create(size_32, stream) → new AP4_SbgpAtom(size, version, flags, stream)
- **描述**: AP4_SbgpAtom 构造函数在第 87 行使用 `if (remains < entry_count * 8)` 来检查 entry_count 是否超出 box 可用字节数，但 `entry_count`（AP4_UI32）与字面量 `8`（int）的乘法在 32-bit 算术下会发生溢出：当 `entry_count ≥ 0x20000000` 时，`entry_count * 8` 的结果为 0 或一个极小值，导致 `remains < 0`（无符号比较）永远为 false，边界检查完全失效。检查通过后，第 90 行 `m_Entries.SetItemCount(entry_count)` 以原始的超大 entry_count 调用 EnsureCapacity，在 32-bit 系统上 `count * sizeof(Entry)` 同样溢出为极小值，导致分配远小于实际需要的内存，后续构造循环对 m_Items[] 的越界写入造成堆破坏；在 64-bit 系统上 EnsureCapacity 尝试分配数 GB 内存，抛出 std::bad_alloc 致进程崩溃。
- **触发条件**: 在 stbl 容器中嵌入一个 sbgp box，entry_count 字段设为 0x20000000 或更大值（使 `entry_count * 8` 在 32-bit 下溢出为 0），box 内提供足够的 `remains` 字节（如 remains = size - 20 = 100）使得溢出后的 `0 > remains` 为 false，从而绕过边界检查。
- **安全影响**: 32-bit 构建上：EnsureCapacity 整数溢出导致堆分配不足，SetItemCount 内的构造循环产生越界写，可通过堆利用达到 RCE；64-bit 构建上：OOM 致进程崩溃（DoS）。

## VULN: AP4_Stz2Atom – Integer overflow in table_size computation yields under-sized buffer and heap OOB read/write
- **漏洞类别**: memory-safety
- **函数**: AP4_Stz2Atom::AP4_Stz2Atom()
- **行号**: 88-121
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-125 (Out-of-bounds Read) / CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → new AP4_File(*input) → AP4_File::ParseStream() → AP4_AtomFactory::CreateAtomFromStream() → AP4_Stz2Atom::Create(size_32, stream) → new AP4_Stz2Atom(size, version, flags, stream)
- **描述**: AP4_Stz2Atom 构造函数先以 `m_Entries.SetItemCount(sample_count)` 预分配条目数组（第 89 行，此处同样无上界检查），然后在第 90 行以 `unsigned int table_size = (sample_count * m_FieldSize + 7) / 8` 计算所需缓冲区字节数。`sample_count`（AP4_UI32）与 `m_FieldSize`（AP4_UI08，取值 4/8/16）的乘法为 32-bit 无符号算术：当 `m_FieldSize=16` 且 `sample_count=0x10000000` 时，`0x10000000 * 16 = 0x100000000` 溢出为 0，table_size 变为 0。随后第 91 行的边界检查 `(0 + 8) > size` 对任意大于 8 的 size 均为 false，检查通过；第 92 行仅分配 0 字节的 buffer，第 93 行 Read(buffer, 0) 成功，之后进入 `case 16` 循环（第 116–118 行），对 `i` 从 0 到 0x10000000-1 执行 `buffer[i*2]`，从 i=1 起即为越界堆读，同时 `m_Entries[i]` 在 32-bit 溢出场景下也越界写回。
- **触发条件**: 在 MP4 文件的 stbl 容器中嵌入一个 stz2 box，field_size 字段（第 4 字节）设为 16，sample_count 字段设为 0x10000000（或满足 `sample_count * m_FieldSize` 32-bit 溢出为 0 的任意值），box size 设为合法的大值使得 `(table_size+8) > size` 检查不触发。
- **安全影响**: 32-bit 构建上：EnsureCapacity 整数溢出导致 m_Entries 仅分配极少内存，后续对 m_Entries[i] 的写入（OOB write）以及 buffer 的越界读（OOB read）共同造成堆破坏，可通过堆利用达到 RCE；64-bit 构建上：SetItemCount 申请约 1 GB 内存，若抛出 bad_alloc 则进程崩溃，m_Items 为 null 时后续访问 m_Entries[0] 导致 null pointer dereference（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
