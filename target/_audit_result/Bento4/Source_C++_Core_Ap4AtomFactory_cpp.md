Now I have enough information. Let me write the final audit report.

## VULN: AP4_CttsAtom 32-bit integer overflow leading to heap OOB read
- **漏洞类别**: memory-safety
- **函数**: AP4_CttsAtom::AP4_CttsAtom()
- **行号**: 79-97
- **CWE**: CWE-190 (Integer Overflow or Wraparound) / CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.8 (AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac → AP4_File::AP4_File() → AP4_AtomFactory::CreateAtomsFromStream() → AP4_AtomFactory::CreateAtomFromStream() → AP4_CttsAtom::Create() → new AP4_CttsAtom(size, version, flags, stream)
- **描述**: 在 Ap4CttsAtom.cpp 第 79-80 行，`entry_count * 8` 的乘法以 `AP4_UI32 * int` 完成（结果类型为 `unsigned int`，32-bit），当 `entry_count >= 0x20000000` 时发生32位整数溢出，导致 `new unsigned char[entry_count*8]` 分配远小于期望的 buffer（如 entry_count=0x20000000 时 buffer 为 0 字节，entry_count=0x20000001 时为 8 字节）。而 `m_Entries.SetItemCount(entry_count)` 内部用 `count * sizeof(T)` 做 64-bit 乘法不溢出，分配了正确大小的 m_Entries 数组（约 1GB）。随后的 `stream.Read(buffer, entry_count*8)` 同样因乘法溢出只读取 0 或少量字节。之后的 for 循环以原始 `entry_count` 次遍历 `buffer[i*8]`，从 i=1 起即访问 buffer 分配范围外的堆内存（OOB 读），并将读取到的堆数据写入 m_Entries。构造函数对 `entry_count` 没有任何与 atom size 的比对校验。
- **触发条件**: 构造一个 ctts atom，atom size 声明为最小值（如 20 字节），但 entry_count 字段值为 0x20000000 或更大，目标系统需有 >=1GB 可用虚拟内存使 SetItemCount 成功
- **安全影响**: 堆越界读：可读取堆上其他对象（如相邻内存分配、堆元数据）的内容到 m_Entries 数组，造成信息泄露；异常的 CTS offset 数据在后续样本表查找时可触发进一步的越界访问，潜在 DoS 或配合其他漏洞实现 RCE

## VULN: AP4_Stz2Atom table_size 32-bit integer overflow leading to heap OOB read
- **漏洞类别**: memory-safety
- **函数**: AP4_Stz2Atom::AP4_Stz2Atom()
- **行号**: 88-120
- **CWE**: CWE-190 (Integer Overflow or Wraparound) / CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 8.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac → AP4_AtomFactory::CreateAtomFromStream() → AP4_Stz2Atom::Create() → new AP4_Stz2Atom(size, version, flags, stream)
- **描述**: Ap4Stz2Atom.cpp 第 90-92 行中，`table_size = (sample_count * m_FieldSize + 7) / 8` 的乘法以 `AP4_Cardinal(unsigned int) * AP4_UI08(unsigned char)` 完成（结果为 32-bit），当 m_FieldSize=8 且 sample_count=0x20000000 时，`0x20000000 * 8 = 0x100000000` 32-bit 溢出为 0，table_size = (0+7)/8 = 0。关键：第 91 行大小校验 `(table_size+8) > size` 使用已溢出的 table_size（值为 0），条件变为 `8 > size`，对任何 size >= 8 的原子均不触发（而 Create 只要求 size >= 12），从而绕过了大小检查。随后 `new unsigned char[0]` 分配 0 字节 buffer，`stream.Read(buffer, 0)` 读 0 字节成功，但 for 循环仍以原始 `sample_count = 0x20000000` 次遍历并访问 `buffer[i]`（case 8），从第一次迭代即发生堆 OOB 读。同时 `m_Entries.SetItemCount(sample_count)` 的 `EnsureCapacity` 用 64-bit 乘法分配 512MB（`0x20000000 * 4`），在内存充足时成功，后续写入 m_Entries 合法但 buffer 读取为 OOB。
- **触发条件**: 构造 stz2 atom，field_size=8（0x08），sample_count=0x20000000，atom 声明 size 可仅为 20 字节，目标系统需有 >=512MB 可用内存
- **安全影响**: 攻击者可从 buffer 之后的堆内存（其他对象、堆元数据、相邻分配）读取 512MB 数据写入 m_Entries，造成大量堆信息泄露；并产生极高 CPU/内存负载构成 DoS

## VULN: AP4_TrunAtom missing sample_count bounds check before heap allocation
- **漏洞类别**: memory-safety
- **函数**: AP4_TrunAtom::AP4_TrunAtom()
- **行号**: 127-151
- **CWE**: CWE-400 (Uncontrolled Resource Consumption) / CWE-789 (Memory Allocation with Excessive Size Value)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac → AP4_AtomFactory::CreateAtomFromStream() → AP4_TrunAtom::Create() → new AP4_TrunAtom(size, version, flags, stream)
- **描述**: Ap4TrunAtom.cpp 第 127 行 `m_Entries.SetItemCount(sample_count)` 在读取 `sample_count` 后没有任何与 atom 大小的边界校验即调用 SetItemCount。`sample_count` 直接来自文件 4-byte 字段（最大 0xFFFFFFFF），EnsureCapacity 将尝试分配 `sample_count * sizeof(Entry)` 字节（Entry 含 4 个 AP4_UI32 字段，sizeof=16），对 sample_count=0x10000000 即需要 1GB。若系统内存不足，`::operator new` 抛出 bad_alloc 或（在 nothrow 系统上）返回 NULL 后 SetItemCount 错误码被忽略，后续 `m_Entries[i].sample_duration = ...` 在 m_Items=NULL 时为空指针解引用，造成进程崩溃。
- **触发条件**: 构造 trun atom，sample_count 字段为超大值（如 0xFFFFFFFF），仅需包含正常头部即可触发
- **安全影响**: 强制目标进程分配极大堆内存直至 OOM，或在 nothrow 分配器下导致空指针解引用，均造成进程崩溃（DoS）

## VULN: AP4_TfraAtom missing entry_count bounds check before heap allocation
- **漏洞类别**: memory-safety
- **函数**: AP4_TfraAtom::AP4_TfraAtom()
- **行号**: 87-88
- **CWE**: CWE-400 (Uncontrolled Resource Consumption) / CWE-789 (Memory Allocation with Excessive Size Value)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac → AP4_AtomFactory::CreateAtomFromStream() → AP4_TfraAtom::Create() → new AP4_TfraAtom(size, version, flags, stream)
- **描述**: Ap4TfraAtom.cpp 第 87-88 行，从文件读取 `entry_count` 后不验证其与 atom size 的关系即调用 `m_Entries.SetItemCount(entry_count)`。tfra Entry 结构含 time(UI64)、moof_offset(UI64)、traf/trun/sample number，sizeof 约 24 字节。entry_count=0x08000000 即需 3GB 分配，造成 bad_alloc 崩溃。此外，若使用 nothrow 分配后 SetItemCount 返回值未被检查，后续循环访问 NULL m_Items 造成空指针解引用。
- **触发条件**: 构造 tfra atom，entry_count 字段为超大值，atom 其余部分可合法（含正确的字段宽度设置）
- **安全影响**: 进程强制消耗大量内存直至 OOM 崩溃，或空指针解引用崩溃，均为 DoS

## VULN: AP4_SaizAtom unsigned integer underflow bypasses entry-count bounds check
- **漏洞类别**: memory-safety
- **函数**: AP4_SaizAtom::AP4_SaizAtom()
- **行号**: 78-101
- **CWE**: CWE-191 (Integer Underflow) / CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac → AP4_AtomFactory::CreateAtomFromStream() → AP4_SaizAtom::Create() → new AP4_SaizAtom(size, version, flags, stream)
- **描述**: Ap4SaizAtom.cpp 第 78 行 `AP4_UI32 remains = size - GetHeaderSize()`（GetHeaderSize()=12），当 atom size=12（Create 允许的最小值）时 remains=0。若 flags bit 0 被置位（攻击者可控），第 82 行 `remains -= 8` 发生无符号下溢：0 - 8 = 0xFFFFFFF8。接着第 86 行 `remains -= 5` = 0xFFFFFFF3（继续溢出）。第 89 行的安全检查 `if (m_SampleCount > remains)` 与 0xFFFFFFF3（约 4GB）比较，任何合理的 m_SampleCount 均通过检查，完全失去保护作用。若攻击者在 atom 数据外（即紧随其后的相邻 atom 的字节）放置大 m_SampleCount 值（可达 0xFFFFFFF3），则 `new AP4_UI08[m_SampleCount]` 尝试分配近 4GB 内存，OOM 崩溃。若 m_SampleCount 为小值，stream.Read 会读取跨越 atom 边界的字节（来自下一个 atom），造成跨 atom 读取敏感数据。
- **触发条件**: 构造 saiz atom，size=12，flags=0x000001（设置 bit 0），version=0；下一个 atom 的前 5 个字节作为 default_sample_info_size 和 m_SampleCount 被读取
- **安全影响**: 通过精心布局使 m_SampleCount 超出 remains 检查后可造成 OOM DoS；配合跨 atom 读取可导致后续处理中使用错误的样本信息大小，产生数据混淆或间接内存访问错误

<!-- AUDIT_PROMPT_VERSION: 1 -->
