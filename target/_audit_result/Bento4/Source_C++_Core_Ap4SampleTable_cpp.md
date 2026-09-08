I've now completed a thorough multi-pass analysis of `Ap4SampleTable.cpp`, `Ap4AtomSampleTable.cpp`, and all key related atom implementations (`Ap4CttsAtom.cpp`, `Ap4StszAtom.cpp`, `Ap4StcoAtom.cpp`, `Ap4Co64Atom.cpp`, `Ap4StscAtom.cpp`, `Ap4Stz2Atom.cpp`, `Ap4SttsAtom.cpp`, `Ap4Array.h`, `Ap4Types.h`). Here are the findings:

- **AP4_CttsAtom** (Ap4CttsAtom.cpp:78–98): `entry_count` read from file has **no bounds check against atom size**, unlike every other table atom (stsc/stsz/stco/stss/co64 all guard with `entry_count > (size – overhead)/element_size`). Additionally, `entry_count * 8` is computed as 32-bit `AP4_UI32` arithmetic and can overflow to 0 or small values. The return value of `m_Entries.SetItemCount(entry_count)` is never checked.
- **AP4_Stz2Atom** (Ap4Stz2Atom.cpp:90): `(sample_count * m_FieldSize + 7) / 8` is a 32-bit multiplication that overflows to 0 for `sample_count ≥ 0x10000000` with `m_FieldSize = 16`, yielding `table_size = 0`, a 0-byte `buffer` allocation, and a loop that reads from `buffer[i*2]` for up to 268M iterations — OOB from the start.
- **AP4_StszAtom** (Ap4StszAtom.cpp:78): The bounds check uses `size - 8` (AP4_ATOM_HEADER_SIZE) but the correct overhead is `size - 20` (8 header + 4 version/flags + 4 sample_size + 4 sample_count), an off-by-12 error that allows stream reads past the atom boundary, injecting attacker-controlled data into the sample size table.

## VULN: AP4_CttsAtom Missing Bounds Check + Integer Overflow → Heap Overflow / Crash
- **漏洞类别**: memory-safety
- **函数**: AP4_CttsAtom::AP4_CttsAtom(AP4_UI32, AP4_UI08, AP4_UI32, AP4_ByteStream&)
- **行号**: 78-98 (Ap4CttsAtom.cpp)
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-Based Buffer Overflow)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac input.mp4 → AP4_File(stream) → AP4_AtomFactory::CreateAtomFromStream → moov→trak→mdia→minf→stbl container parsing → AP4_CttsAtom::Create(size, stream) → AP4_CttsAtom::AP4_CttsAtom(size, version, flags, stream) → heap corruption
- **描述**: 在 Ap4CttsAtom.cpp 第 78 行，构造函数从文件控制的字节流中读取 entry_count（AP4_UI32），完全没有对其与原子 size 进行任何边界校验。这与同类原子（stsc/stsz/stco/co64/stss）形成鲜明对比——后者均有 `entry_count > (size – overhead) / element_size` 的保护。随后：(1) 第 79 行 `m_Entries.SetItemCount(entry_count)` 的返回值未被检查；(2) 第 80 行 `new unsigned char[entry_count*8]` 中，`entry_count * 8` 作为 AP4_UI32 算术运算，当 entry_count = 0x20000000 时溢出为 0；在 AP4_Array::EnsureCapacity 中，32 位系统上 `count * sizeof(AP4_CttsTableEntry)` 同样溢出为 0，`::operator new(0)` 返回合法小型分配，随后 SetItemCount 的构造循环对 entry_count × 8 字节逐一写入 → 巨量堆溢出；64 位系统上 4 GB 分配失败抛出 std::bad_alloc 或返回 NULL，进入后续循环时 m_Entries.m_Items 为 NULL → 空指针解引用 crash。
- **触发条件**: 构造包含 moov/trak/mdia/minf/stbl/ctts box 的 MP4 文件，将 ctts 的 entry_count 字段设为 0x20000000（536870912），atom size 设为最小合法值（如 16 字节），实际数据区为空。工具命令：`mp42aac crafted.mp4 output.aac`。
- **安全影响**: 32 位系统：堆缓冲区溢出，攻击者可覆盖堆元数据及后续分配对象，在足够的堆布局控制下可实现远程代码执行（RCE）。64 位系统（默认）：进程因未捕获的 std::bad_alloc 或空指针解引用崩溃，DoS。若以 -fno-exceptions 编译（Android 常见配置），空指针解引用路径同样导致 SIGSEGV crash。

## VULN: AP4_Stz2Atom Integer Overflow in table_size → Heap OOB Read
- **漏洞类别**: memory-safety
- **函数**: AP4_Stz2Atom::AP4_Stz2Atom(AP4_UI32, AP4_UI08, AP4_UI32, AP4_ByteStream&)
- **行号**: 88-120 (Ap4Stz2Atom.cpp)
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 6.1 (AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac input.mp4 → AP4_File → AP4_AtomFactory → moov→trak→mdia→minf→stbl → AP4_Stz2Atom::Create(size, stream) → AP4_Stz2Atom::AP4_Stz2Atom(size, version, flags, stream) → heap OOB read
- **描述**: 第 90 行 `unsigned int table_size = (sample_count*m_FieldSize+7)/8`，其中 sample_count 为 AP4_UI32，m_FieldSize 可为 4/8/16。当 m_FieldSize=16 且 sample_count=0x10000000 时，`0x10000000 * 16 = 0x100000000` 作为 32 位无符号乘法溢出为 0，table_size=0。随后第 91 行的边界检查 `(0+8) > size` 在 size >= 8 时通过，`new unsigned char[0]` 分配零字节缓冲区，`stream.Read(buffer, 0)` 读取 0 字节。最终在 case 16 中，循环 `for(i=0; i<0x10000000; i++) { m_Entries[i] = AP4_BytesToUInt16BE(&buffer[i*2]); }` 从 i=1 开始即访问 buffer[2]、buffer[4] 等——全部超出零字节分配边界，造成堆越界读取，将相邻堆内存（堆元数据、其他对象数据）解释为采样大小。
- **触发条件**: 构造含 stz2 box 的 MP4，field_size=16，sample_count=0x10000000（268435456）；系统需有足够内存使 m_Entries.SetItemCount(0x10000000) 的 256MB 分配成功（m_Entries 为 AP4_Array<AP4_UI32>，4 × 0x10000000 = 1 GB）。
- **安全影响**: 堆越界读，可泄露相邻堆对象内容（信息泄露），所读到的堆元数据若被当作采样大小使用，可能进一步影响后续文件偏移计算逻辑，导致进程崩溃（DoS）或在特殊堆布局下进一步利用。

## VULN: AP4_StszAtom Wrong Bounds Constant Allows OOB Stream Read into Sample Size Table
- **漏洞类别**: memory-safety
- **函数**: AP4_StszAtom::AP4_StszAtom(AP4_UI32, AP4_UI08, AP4_UI32, AP4_ByteStream&)
- **行号**: 78-97 (Ap4StszAtom.cpp)
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 5.5 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac input.mp4 → AP4_File → AP4_AtomFactory → moov→trak→mdia→minf→stbl → AP4_StszAtom::Create(size, stream) → AP4_StszAtom::AP4_StszAtom(size, version, flags, stream) → OOB stream read → sample size table poisoning
- **描述**: 第 78 行的溢出检查 `if (m_SampleCount > (size-8)/4)` 使用了错误的常量 8（`AP4_ATOM_HEADER_SIZE`），而正确的消耗字节数应为 20（8 基本头 + 4 version/flags + 4 sample_size + 4 sample_count），即应为 `(size-20)/4`。当前检查允许最多 `(size-8)/4` 条目，比实际可用条目多 3 个（off-by-12 字节 / 3 条目）。攻击者构造 size=20 的 stsz 原子并设 m_SampleCount=1：检查通过（`1 <= (20-8)/4 = 3`），但 atom 中不含任何条目数据（20 字节全为头部）。`stream.Read(buffer, 4)` 读取 stsz box 之后的 4 字节——即下一个 box（如 stco）的内容，将其作为采样大小存入 m_Entries。攻击者通过精心放置紧随其后的数据，向采样大小表注入任意值。
- **触发条件**: 构造 MP4，stsz 原子大小设为 20（最小含 SampleCount 字段的合法大小），m_SampleSize=0，m_SampleCount=1；紧随其后放置携带攻击载荷的下一个原子（如 stco），其前 4 字节被读取为采样大小。
- **安全影响**: 相邻 box 的任意 4 字节被当作采样大小读入，导致后续 AP4_AtomSampleTable::GetSample 中的偏移量（chunk offset + 累计采样大小）被攻击者控制，可将音频数据读取重定向到文件中的任意位置，造成文件内容越界读取（信息泄露）或触发后续处理逻辑错误。

<!-- AUDIT_PROMPT_VERSION: 1 -->
