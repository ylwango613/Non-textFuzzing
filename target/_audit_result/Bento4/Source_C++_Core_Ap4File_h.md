I now have complete coverage of all critical atoms. Let me verify the stsz bounds check arithmetic one final time before writing the report.

**Key findings from the deep analysis:**

- `AP4_Size` = `AP4_UI32` = `unsigned int` (32-bit) — all size multiplications are 32-bit
- `AP4_FULL_ATOM_HEADER_SIZE = 12`, `AP4_ATOM_HEADER_SIZE = 8`

**Finding A — `Ap4CttsAtom.cpp` lines 77-98**: No bounds check on `entry_count`; `entry_count*8` (uint32_t) overflows to 0 when entry_count ≥ 0x20000000 → zero-size buffer, stream.Read(0 bytes) returns AP4_SUCCESS → for-loop runs entry_count times accessing buffer[i*8] OOB. Requires ~4 GB for SetItemCount.

**Finding B — `Ap4Stz2Atom.cpp` lines 88-120**: `table_size = (sample_count*m_FieldSize+7)/8`; with m_FieldSize=16, sample_count=0x10000000, multiplication overflows to 0 → table_size=0 → guard `(0+8)>size` is false for any valid atom → 0-byte buffer → loop reads buffer[i*2] OOB. Requires ~1 GB for SetItemCount.

**Finding C — `Ap4StszAtom.cpp` line 78**: Guard uses `(size-8)/4` but should be `(size-20)/4` (header=12, sample_size=4, sample_count=4 = 20 bytes consumed). Allows up to 3 extra sample entries → `stream.Read` reads up to 12 bytes past the declared atom boundary from the next atom.

## VULN: stz2 integer overflow sample_count*m_FieldSize leads to heap buffer over-read
- **漏洞类别**: memory-safety
- **函数**: `AP4_Stz2Atom::AP4_Stz2Atom(AP4_UI32, AP4_UI08, AP4_UI32, AP4_ByteStream&)`
- **行号**: 88-120
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.1 (AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: `main() → AP4_File(stream) → ParseStream() → AP4_DefaultAtomFactory::CreateAtomFromStream() → AP4_Stz2Atom::Create(size, stream) → new AP4_Stz2Atom(size, version, flags, stream)` → 构造函数内 `table_size = (sample_count*m_FieldSize+7)/8` 整数溢出
- **描述**: 在 `Ap4Stz2Atom.cpp` 第 90 行，`sample_count`（AP4_UI32）与 `m_FieldSize`（AP4_UI08）相乘时使用 32 位无符号算术：`unsigned int table_size = (sample_count*m_FieldSize+7)/8`。当攻击者在 MP4 文件中将 `m_FieldSize` 设为 16、`sample_count` 设为 0x10000000 时，`0x10000000 * 16 = 0x100000000` 发生 uint32_t 溢出，截断为 0，导致 `table_size = (0+7)/8 = 0`。随后的保护检查 `if ((table_size+8) > size) return;` 变为 `8 > size`，对于任何合法原子（size ≥ 12）均为 false，无法拦截。接着 `new unsigned char[0]` 分配零字节缓冲区，`stream.Read(buffer, 0)` 读取 0 字节且返回成功。随后 for 循环（case 16）对 `i=0..sample_count-1` 执行 `m_Entries[i] = AP4_BytesToUInt16BE(&buffer[i*2])`，从零字节缓冲区越界读取堆内存（从 buffer[0] 起即为 OOB），覆写整个 m_Entries 数组。
- **触发条件**: 构造含 `m_FieldSize=16`、`sample_count=0x10000000` 的 stz2 box（只需 20 字节），无需实际样本数据。运行环境需有约 1 GB 空闲堆内存供 `m_Entries.SetItemCount(0x10000000)` 分配（`AP4_Array<AP4_UI32>` 每项 4 字节，共 1 GB）。
- **安全影响**: 堆越界读取可泄露堆元数据及相邻分配内容；循环随 i 增大持续读取越来越远的堆内存，最终触发 SIGSEGV 崩溃（拒绝服务）；被污染的 m_Entries 样本尺寸可传播至后续 GetSampleSize() 调用，在处理媒体样本时引发进一步的非法内存访问；若通过受控文件偏移可构造 RCE 原语。

## VULN: ctts atom integer overflow entry_count*8 leads to heap buffer over-read
- **漏洞类别**: memory-safety
- **函数**: `AP4_CttsAtom::AP4_CttsAtom(AP4_UI32, AP4_UI08, AP4_UI32, AP4_ByteStream&)`
- **行号**: 77-98
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 6.5 (AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: `main() → AP4_File(stream) → ParseStream() → AP4_DefaultAtomFactory::CreateAtomFromStream() → AP4_CttsAtom::Create(size, stream) → new AP4_CttsAtom(size, version, flags, stream)` → 构造函数内 `new unsigned char[entry_count*8]` 整数溢出
- **描述**: 在 `Ap4CttsAtom.cpp` 第 77-98 行，ctts 原子构造函数对 `entry_count` 没有任何上界检查（对比 stsz 有 `(size-8)/4` 检查，ctts 完全缺失）。第 80 行 `unsigned char* buffer = new unsigned char[entry_count*8]`，当 `entry_count`（AP4_UI32）等于 0x20000000 时，`0x20000000 * 8 = 0x100000000` 在 32 位无符号运算下溢出截断为 0，分配零字节缓冲区。第 81 行 `stream.Read(buffer, entry_count*8)` 因 `entry_count*8=0` 读取 0 字节并返回 AP4_SUCCESS。第 88 行循环随后对 `i = 0..entry_count-1` 执行 `AP4_BytesToUInt32BE(&buffer[i*8])` 和 `AP4_BytesToUInt32BE(&buffer[i*8+4])`，从零字节缓冲区开始堆越界读取，将结果写入 `m_Entries[i].m_SampleCount` 和 `m_Entries[i].m_SampleOffset`。
- **触发条件**: 构造含 `entry_count=0x20000000` 的 ctts box（最小 20 字节即可）。`m_Entries.SetItemCount(0x20000000)` 分配 `AP4_CttsTableEntry`（8 字节/项）× 0x20000000 ≈ 4 GB。需约 4 GB 可用内存；内存不足时 std::bad_alloc 导致崩溃（DoS），内存充足时触发 OOB 读。
- **安全影响**: 读取堆元数据及相邻分配内容后写入 ctts 时间偏移表，导致 CTS 计算异常；循环最终触发非法地址访问造成进程崩溃（DoS）；泄露堆布局信息（信息泄露）。

## VULN: stsz atom incorrect overflow guard reads 12 bytes past declared atom boundary
- **漏洞类别**: memory-safety
- **函数**: `AP4_StszAtom::AP4_StszAtom(AP4_UI32, AP4_UI08, AP4_UI32, AP4_ByteStream&)`
- **行号**: 76-97
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 5.3 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:L)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: `main() → AP4_File(stream) → ParseStream() → AP4_DefaultAtomFactory::CreateAtomFromStream() → AP4_StszAtom::Create(size, stream) → new AP4_StszAtom(size, version, flags, stream)` → 构造函数内错误的上界检查允许读取超出 atom 声明范围的字节
- **描述**: `Ap4StszAtom.cpp` 第 78 行的上界检查 `if (m_SampleCount > (size-8)/4)` 使用了错误的常量。stsz full atom 实际消耗字节数为：8（基本头）+ 4（version/flags）+ 4（sample_size 字段）+ 4（sample_count 字段）= 20 字节，因此正确公式应为 `(size-20)/4`。但代码使用 `(size-8)/4`，比正确值多出 `(20-8)/4 = 3` 个条目，即允许声明最多比 atom 实际容纳数量多 3 个样本。当 `m_SampleCount = (size-8)/4` 时（check 通过），第 86-87 行 `new unsigned char[sample_count*4]` 分配正确大小的缓冲区，但 `stream.Read(buffer, sample_count*4)` 会从文件流中读取超出 atom 声明边界的最多 12 字节——这 12 字节属于下一个 atom（例如 stco 的 size/type 字段）。这 12 字节随后被解析为样本大小写入 `m_Entries`，造成跨原子数据污染（OOB 读）。
- **触发条件**: 构造 stsz box，其中 `sample_size=0`（启用变长模式），`sample_count` 设置为恰好等于 `(box_size-8)/4`（即高于实际可容纳数量 3 个），后续紧跟任意 box。例如：box size=28（容纳 2 个有效条目），sample_count=5，check `5 > (28-8)/4=5` 为 false，然后 stream.Read 读取 20 字节：8 字节来自 atom 内有效数据 + 12 字节来自下一个 atom。
- **安全影响**: 被污染的样本尺寸表导致 `GetSample()` 内的 `offset += size` 计算使用非法偏移量，进而在解析媒体数据时寻址文件的错误位置；样本数据被误读并写入输出 AAC 文件（信息泄露）；若后续代码对样本大小未做验证，可能触发下游内存分配异常，进而影响程序稳定性（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
