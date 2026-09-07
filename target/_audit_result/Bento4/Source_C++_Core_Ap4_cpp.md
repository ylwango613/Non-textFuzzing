Based on my thorough analysis of the Core parsing files, I have identified multiple memory safety vulnerabilities. Here are the final findings:

## VULN: AP4_Stz2Atom Integer Overflow → Heap Buffer Over-read
- **漏洞类别**: memory-safety
- **函数**: AP4_Stz2Atom::AP4_Stz2Atom()
- **行号**: 88-120
- **CWE**: CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 8.1 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac → AP4_File → AP4_AtomFactory::CreateAtomFromStream → AP4_Stz2Atom::Create → AP4_Stz2Atom::AP4_Stz2Atom(size, version, flags, stream)
- **描述**: 在 `Ap4Stz2Atom.cpp:90`，`table_size = (sample_count*m_FieldSize+7)/8` 中，`sample_count`（`uint32_t`）与 `m_FieldSize`（`uint8_t`，值为 4/8/16 之一）相乘时发生 32 位无符号整数溢出。当 `m_FieldSize=16, sample_count=0x10000000` 时，乘积 `0x100000000` 截断为 0，`table_size=0`，导致 `new unsigned char[0]` 分配零字节缓冲区。随后的循环 `for (i=0; i<sample_count; i++) m_Entries[i] = AP4_BytesToUInt16BE(&buffer[i*2])` 对 0 字节缓冲区进行越界读取，读出相邻堆内存并写入 `m_Entries[i]`（有效已分配空间）。前置的 `m_Entries.SetItemCount(0x10000000)` 仅需 256 MB（uint32_t 数组），在现代 64 位系统上完全可行；边界检查 `(table_size+8)>size` 因 `table_size=0` 而始终为假无法阻止后续行为。
- **触发条件**: 在 MP4 文件中嵌入一个 stz2 box（box type `STZ2`），其中 `field_size=16`，`sample_count=0x10000000`，box 本体只需约 20 字节（正常小盒子）。
- **安全影响**: 越界读取堆内存中紧邻零字节分配的数据（可泄漏堆布局、指针、密钥材料等敏感信息），同时在大规模循环中引发段错误，导致进程崩溃（DoS）。在开启 ASAN 的测试环境下可被模糊测试直接捕获为 heap-buffer-overflow。

## VULN: AP4_CttsAtom Missing Bounds Check Plus Integer Overflow → Heap Buffer Over-read
- **漏洞类别**: memory-safety
- **函数**: AP4_CttsAtom::AP4_CttsAtom()
- **行号**: 77-97
- **CWE**: CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 7.4 (AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac → AP4_File → AP4_AtomFactory::CreateAtomFromStream → AP4_CttsAtom::Create → AP4_CttsAtom::AP4_CttsAtom(size, version, flags, stream)
- **描述**: 在 `Ap4CttsAtom.cpp:77-97`，ctts atom 构造函数直接用文件中读取的 `entry_count`（`uint32_t`）进行分配，而没有执行同类 box（stco/co64/stsc/stsz）均有的 `entry_count <= (size - header) / entry_size` 边界检查。第 80 行 `new unsigned char[entry_count*8]`：当 `entry_count >= 0x20000000` 时，`entry_count * 8`（`uint32_t` 运算）溢出为 0，分配零字节缓冲区。随后 `stream.Read(buffer, 0)` 返回成功（读 0 字节），`m_Entries.SetItemCount(entry_count)` 的返回值被忽略，循环 `for (i=0; i<entry_count; i++) m_Entries[i].m_SampleCount = AP4_BytesToUInt32BE(&buffer[i*8])` 越界读取 `buffer`（heap OOB read）。对 `m_Entries[i]` 的写入若 `m_Items` 为 NULL（nothrow 分配器失败后 SetItemCount 错误码被忽略）则产生 NULL 指针写入崩溃。
- **触发条件**: 构造包含 ctts box 的 MP4 文件，将 `entry_count` 字段设置为 `0x20000000` 或更大。在 4 GB+ 可用堆的 64 位系统（或启用内存过度提交的 Linux）上，SetItemCount 分配 4 GB 后触发 OOB read；在无异常或 nothrow 环境中触发 NULL deref write。
- **安全影响**: 堆越界读取导致相邻堆内存泄漏（信息泄露），或进程崩溃（DoS）。与 stco/co64/stsc/stsz 的安全差距对比明确，属典型 missing input validation → 内存破坏。

## VULN: AP4_SbgpAtom Bounds-Check Integer Overflow → Check Bypass → OOM/Null Deref
- **漏洞类别**: memory-safety
- **函数**: AP4_SbgpAtom::AP4_SbgpAtom()
- **行号**: 87-95
- **CWE**: CWE-190 (Integer Overflow or Wraparound)
- **CVSS v3.1**: 6.5 (AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac → AP4_File → AP4_AtomFactory::CreateAtomFromStream → AP4_SbgpAtom::Create → AP4_SbgpAtom::AP4_SbgpAtom(size, version, flags, stream)
- **描述**: 在 `Ap4SbgpAtom.cpp:87`，边界检查 `if (remains < entry_count*8)` 中 `entry_count*8` 为 `uint32_t` 运算，当 `entry_count >= 0x20000000` 时乘积溢出为 0，使 `remains < 0`（uint32_t 比较）永远为 false，边界检查完全失效。随后 `m_Entries.SetItemCount(entry_count)` 以攻击者指定的超大 entry_count 分配内存，在标准 C++ 下触发 `std::bad_alloc` 崩溃（DoS）；在 nothrow 环境中 SetItemCount 的错误返回值被忽略，随后 `m_Entries[i] = entry` 写入 NULL 指针（内存破坏）。
- **触发条件**: 构造 sbgp box，将 `entry_count` 设置为 `0x20000000`，确保 box 中 `remains` 非零（≥ 1 字节剩余）以代入比较。
- **安全影响**: DoS（进程因未捕获 bad_alloc 崩溃）或 nothrow 平台上 NULL 指针写入破坏内存完整性。

## VULN: AP4_SaioAtom Bounds-Check Integer Overflow → Check Bypass → OOM/Null Deref
- **漏洞类别**: memory-safety
- **函数**: AP4_SaioAtom::AP4_SaioAtom()
- **行号**: 110-113
- **CWE**: CWE-190 (Integer Overflow or Wraparound)
- **CVSS v3.1**: 6.5 (AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac → AP4_File → AP4_AtomFactory::CreateAtomFromStream → AP4_SaioAtom::Create → AP4_SaioAtom::AP4_SaioAtom(size, version, flags, stream)
- **描述**: 在 `Ap4SaioAtom.cpp:110`，边界检查 `if (remains < entry_count*(m_Version==0?4:8))` 中乘法为 `uint32_t` 运算，当 version=0 且 `entry_count >= 0x40000000` 时，`entry_count*4` 溢出为 0，绕过检查，允许后续 `m_Entries.SetItemCount(entry_count)` 接受攻击者控制的超大值，触发 OOM 崩溃（DoS）或 nothrow 下空指针写入（内存破坏）。与 sbgp 同构型漏洞，触发阈值不同（version=1 时 entry_count >= 0x20000000）。
- **触发条件**: 构造 saio box（version=0），设置 `entry_count=0x40000000`，box 中保留足够 `remains`（≥ 1）。
- **安全影响**: DoS（bad_alloc 崩溃）或 nothrow 平台内存破坏。

## VULN: AP4_TrunAtom Unchecked sample_count → Unbounded SetItemCount
- **漏洞类别**: memory-safety
- **函数**: AP4_TrunAtom::AP4_TrunAtom()
- **行号**: 104-151
- **CWE**: CWE-789 (Memory Allocation with Excessive Size Value)
- **CVSS v3.1**: 5.5 (AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac → AP4_File → AP4_AtomFactory::CreateAtomFromStream → AP4_TrunAtom::Create → AP4_TrunAtom::AP4_TrunAtom(size, version, flags, stream)
- **描述**: 在 `Ap4TrunAtom.cpp:127`，`m_Entries.SetItemCount(sample_count)` 在没有任何 `sample_count <= (size - header) / per_entry_size` 边界检查的情况下，直接使用从文件中读取的 `sample_count`（`uint32_t`）。攻击者可将 `sample_count` 设置为 0xFFFFFFFF，触发对 `sizeof(Entry) * 0xFFFFFFFF` 字节的分配请求（标准 C++ 下抛出 `std::bad_alloc`，DoS），SetItemCount 的失败返回值被忽略；在 nothrow 环境下后续循环中 `m_Entries[i]` 产生空指针写入，导致内存破坏。
- **触发条件**: 构造包含 trun box 的分片 MP4，将 `sample_count` 设置为极大值（如 0x10000000）。
- **安全影响**: DoS（进程崩溃），或 nothrow 平台上空指针写入引发内存破坏。

## VULN: AP4_TfraAtom Unchecked entry_count → Unbounded SetItemCount
- **漏洞类别**: memory-safety
- **函数**: AP4_TfraAtom::AP4_TfraAtom()
- **行号**: 86-181
- **CWE**: CWE-789 (Memory Allocation with Excessive Size Value)
- **CVSS v3.1**: 5.5 (AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac → AP4_File → AP4_AtomFactory::CreateAtomFromStream → AP4_TfraAtom::Create → AP4_TfraAtom::AP4_TfraAtom(size, version, flags, stream)
- **描述**: 在 `Ap4TfraAtom.cpp:88`，`m_Entries.SetItemCount(entry_count)` 直接使用文件中读取的 `entry_count`（`uint32_t`），无任何边界检查。攻击者可将 `entry_count` 设置为极大值（如 0x10000000），触发 `sizeof(Entry) * entry_count` 字节的堆分配，在标准 C++ 中因 `std::bad_alloc` 崩溃（DoS）；SetItemCount 返回值被忽略，在 nothrow 平台上后续循环中 `m_Entries[i]` 写入 NULL 指针（内存破坏）。
- **触发条件**: 构造包含 mfra/tfra box 的 MP4 文件，将 `entry_count` 设置为 0x10000000 或更大。
- **安全影响**: DoS（进程崩溃），或 nothrow 平台上空指针写入引发内存破坏。

<!-- AUDIT_PROMPT_VERSION: 1 -->
