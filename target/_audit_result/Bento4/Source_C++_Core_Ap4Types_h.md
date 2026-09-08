I now have full understanding of all relevant vulnerabilities. Writing the final report:

## VULN: ctts atom missing entry_count bounds check → integer overflow in buffer allocation → heap OOB read + DoS
- **漏洞类别**: memory-safety
- **函数**: AP4_CttsAtom::AP4_CttsAtom()
- **行号**: 77-98 (Ap4CttsAtom.cpp)
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-125 (Out-of-Bounds Read) / CWE-789 (Uncontrolled Memory Allocation)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_File(*input) → AP4_AtomFactory::CreateAtomFromStream() → AP4_CttsAtom::Create(size_32, stream) → AP4_CttsAtom::AP4_CttsAtom()
- **描述**: `entry_count` 字段（AP4_UI32，来自 Ap4Types.h 的类型定义）直接从文件流读取（第78行），没有任何上界校验，即可传入 m_Entries.SetItemCount(entry_count)（第79行）以及 `new unsigned char[entry_count*8]`（第80行）。第80行的乘法 `entry_count * 8` 以 AP4_UI32（32位无符号整数）运算：当 entry_count ≥ 0x20000000 时结果溢出并截断为小于真实所需的值（例如 entry_count=0x20000000 时截断为0），导致分配的 buffer 远小于循环实际访问的字节数。随后第88行的循环以完整 entry_count 次迭代读取 `buffer[i*8]`，对所有 i > 0 均越界访问堆内存。在任意 entry_count（file-controlled）超过"可用内存/8"时，m_Entries.SetItemCount() 内部的 EnsureCapacity() 调用 ::operator new()（无 nothrow，未被 try-catch 保护）抛出 std::bad_alloc，导致进程崩溃（可靠 DoS）。在32位构建中，EnsureCapacity 的 count*sizeof(T) 同样溢出为0，导致堆底层分配0字节但后续 placement-new 写入数十亿个元素，形成堆缓冲区溢出（潜在 RCE）。
- **触发条件**: MP4文件的 ctts atom 将 entry_count 字段设置为任意大值（如 0xFFFFFFFF 可靠触发 DoS；entry_count=0x20000000 且目标有 ≥4GB 空闲内存时可触发堆越界读）。ctts atom 合法存在于 moov/trak/mdia/minf/stbl/ctts 层次，无需特殊权限或认证。
- **安全影响**: 可靠 DoS（进程崩溃，任意 entry_count 超过系统可用内存的1/8即可触发）；特定条件下堆越界读（heap OOB read）可泄露进程堆内存内容；32位构建下升级为堆缓冲区溢出，具备 RCE 潜力。

## VULN: stco/co64 bounds check整数下溢导致不受控制的巨型内存分配（DoS）
- **漏洞类别**: memory-safety
- **函数**: AP4_StcoAtom::AP4_StcoAtom() / AP4_Co64Atom::AP4_Co64Atom()
- **行号**: 78-82 (Ap4StcoAtom.cpp) / 78-81 (Ap4Co64Atom.cpp)
- **CWE**: CWE-191 (Integer Underflow/Wrap-around) → CWE-789 (Uncontrolled Memory Allocation)
- **CVSS v3.1**: 5.5 (AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_File(*input) → AP4_AtomFactory::CreateAtomFromStream() → AP4_StcoAtom::Create(size_32, stream) → AP4_StcoAtom::AP4_StcoAtom()
- **描述**: Create() 入口检查 `size < AP4_FULL_ATOM_HEADER_SIZE (=12)`，因此 size=12 的 atom 可通过检查。构造函数第78行的上界校验计算 `(size - AP4_FULL_ATOM_HEADER_SIZE - 4) / 4 = (size - 16) / 4`，当 size 处于 [12, 15] 时，减法 `size - 16` 以 AP4_UI32 无符号运算发生向下溢出（underflow），例如 size=12 时结果为 0xFFFFFFFC / 4 = 0x3FFFFFFF（约10亿），本应限制为0的上界变成了约10亿。文件中声明的 m_EntryCount 只要不超过 0x3FFFFFFF 便不会被截断，随后 `new AP4_UI32[0x3FFFFFFF]`（约4GB）与 `new unsigned char[0x3FFFFFFF*4]`（约4GB）相继触发 std::bad_alloc，进程在无 try-catch 保护的情况下崩溃。co64 atom 存在完全相同的问题（除以数改为8，上界变为 0x1FFFFFFF，单次分配约4GB AP4_UI64）。
- **触发条件**: 构造 moov/trak/mdia/minf/stbl/stco box，将其 size 字段设为 12（或13-15），entry_count 字段设为 0x3FFFFFFF。MP4 文件体积可极小（整个文件只需约30-50字节），但会导致进程尝试分配数GB内存。
- **安全影响**: 可靠 Denial of Service（进程崩溃）；可用于构造极小 MP4 文件触发不成比例的内存消耗。

<!-- AUDIT_PROMPT_VERSION: 1 -->
