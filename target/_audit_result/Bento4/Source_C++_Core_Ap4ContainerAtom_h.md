Based on my comprehensive analysis of `Ap4ContainerAtom.h/.cpp` and all related atom parsers, here are the confirmed memory safety vulnerabilities:

## VULN: AP4_CttsAtom Integer Overflow → Heap Buffer Over-Read / Overflow
- **漏洞类别**: memory-safety
- **函数**: AP4_CttsAtom::AP4_CttsAtom()
- **行号**: 77-97 (Ap4CttsAtom.cpp)
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-125 (Out-of-bounds Read) / CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_File / AP4_Movie constructor → AP4_DefaultAtomFactory::CreateAtomFromStream() → AP4_AtomFactory::CreateAtomFromStream() → AP4_CttsAtom::Create(size_32, stream) → new AP4_CttsAtom(size, version, flags, stream)
- **描述**: `AP4_CttsAtom` 构造函数直接从流中读取 `entry_count`（AP4_UI32，攻击者完全控制），既没有将其与 atom 声明的 `size` 字段做上界校验，也没有检查后续分配是否溢出。第80行 `new unsigned char[entry_count*8]`：`entry_count`（unsigned int）与字面量 `8`（int）相乘，结果类型为 unsigned int（32-bit），当 `entry_count >= 0x20000000` 时，乘积 `0x100000000` 截断为 `0`，实际分配 0 字节（但有效指针）。第81行 `stream.Read(buffer, entry_count*8)` 传入同一溢出后的 `0`，读取 0 字节成功返回。随后 `for` 循环对 `buffer[i*8]` 与 `buffer[i*8+4]` 的访问（i≥0）立即越界，从相邻堆内存读取数据（OOB read）。在第79行 `m_Entries.SetItemCount(entry_count)` 路径：64-bit 系统上 `EnsureCapacity` 会尝试分配 4 GB，OOM 失败时 `m_Items` 保持 NULL，后续 `m_Entries[i]` 在循环中造成 NULL 指针解引用；32-bit 系统上 `count * sizeof(T)` 同样溢出为 0，placement new 循环立即写越 0 字节缓冲区，形成堆缓冲区溢出（写）。
- **触发条件**: 构造一个 MP4 文件，其 `stbl` 容器中包含一个 `ctts` atom，atom 的 4 字节 `entry_count` 字段设置为 `0x20000000`（或任何使 `entry_count * 8` 对 2^32 取模后为小值的数），atom 的 `size` 字段可设置为最小合法值（12 字节），无需其他特殊条件。
- **安全影响**: 32-bit 平台上堆缓冲区覆写可实现任意代码执行（RCE）；64-bit 平台上触发堆相邻内存越界读（信息泄露）或因 NULL 解引用导致进程崩溃（DoS）。

## VULN: AP4_TrunAtom Unvalidated sample_count → Null Pointer Dereference / Heap Overflow
- **漏洞类别**: memory-safety
- **函数**: AP4_TrunAtom::AP4_TrunAtom()
- **行号**: 104-151 (Ap4TrunAtom.cpp)
- **CWE**: CWE-476 (NULL Pointer Dereference) / CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 6.1 (AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_DefaultAtomFactory::CreateAtomFromStream() → AP4_TrunAtom::Create(size_32, stream) → new AP4_TrunAtom(size, version, flags, stream)
- **描述**: 构造函数第105行从流中读取 `sample_count`（AP4_UI32），第127行调用 `m_Entries.SetItemCount(sample_count)` 但未检查返回值，也未将 `sample_count` 与 atom `size` 字段做上界校验。`AP4_TrunAtom::Entry` 为 16 字节，`EnsureCapacity(sample_count)` 在 64-bit 平台上计算 `(size_t)sample_count * 16`：当 `sample_count = 0x10000000` 时尝试分配 4 GB，OOM 失败后 `m_Items` 保持 NULL、`m_ItemCount` 保持 0，但 `SetItemCount` 的错误返回值被忽略。随后第128-151行循环 `for (i=0; i<sample_count; i++)` 对 `m_Entries[i]`（即 `m_Items[i]`）直接解引用，造成 NULL 指针解引用；32-bit 平台上 `sample_count * 16` 同样溢出为 0，SetItemCount 中 placement new 循环越 0 字节缓冲区写入，形成堆缓冲区溢出。
- **触发条件**: 构造包含 fragmented MP4（moof/traf/trun）结构的 MP4 文件，trun atom 的 `sample_count` 字段设置为 `0x10000000` 或更大值，atom `size` 可为最小值（12 字节）。
- **安全影响**: 64-bit 平台上 NULL 指针解引用导致进程崩溃（DoS）；32-bit 平台上堆缓冲区溢出可能实现任意代码执行。

## VULN: AP4_StcoAtom/AP4_Co64Atom Unsigned Integer Underflow Bypasses Bounds Check → OOM Heap Allocation
- **漏洞类别**: memory-safety
- **函数**: AP4_StcoAtom::AP4_StcoAtom() / AP4_Co64Atom::AP4_Co64Atom()
- **行号**: 78-82 (Ap4StcoAtom.cpp) / 78-81 (Ap4Co64Atom.cpp)
- **CWE**: CWE-191 (Integer Underflow) → CWE-789 (Memory Allocation with Excessive Size Value)
- **CVSS v3.1**: 5.5 (AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_DefaultAtomFactory::CreateAtomFromStream() → AP4_StcoAtom::Create(size_32, stream) → new AP4_StcoAtom(size, version, flags, stream)
- **描述**: `AP4_StcoAtom` 构造函数第78行的上界校验 `m_EntryCount > (size - AP4_FULL_ATOM_HEADER_SIZE - 4) / 4` 在 `size < AP4_FULL_ATOM_HEADER_SIZE + 4 = 16` 时发生无符号整数下溢：`Create` 仅检查 `size >= AP4_FULL_ATOM_HEADER_SIZE = 12`，故 size ∈ {12,13,14,15} 均可通过。以 size=12 为例，`(12 - 12 - 4) / 4 = 0xFFFFFFFC / 4 = 0x3FFFFFFF`，校验实际放行最多 0x3FFFFFFF 条目。第81行 `new AP4_UI32[m_EntryCount]` 与第82行 `new unsigned char[m_EntryCount * 4]` 均尝试分配约 4 GB，触发进程级 OOM 崩溃。`AP4_Co64Atom` 第78行有完全相同的模式（除数从 4 改为 8）。
- **触发条件**: 构造包含 `stco` atom 的 MP4 文件，atom `size` 字段设置为 12（最小合法值），`entry_count` 字段设置为大于 0 的任意值（如 1），在 32-bit 上 entry_count 约 0x3FFFFFFF 可触发；在 64-bit 上任意非零值都会使分配尝试超过 4 GB。
- **安全影响**: 进程因无法满足超大内存分配请求而崩溃（std::bad_alloc 或 SIGABRT），造成拒绝服务（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
