I now have all the information needed for a complete analysis. Let me compile the final findings.

**Group 1 analysis — ctts (Ap4CttsAtom.cpp:77-80)**

- No bounds check on `entry_count` before `SetItemCount` (unlike stco which clamps)
- `m_Entries.SetItemCount(entry_count)` → `EnsureCapacity(entry_count)` → `::operator new(entry_count * sizeof(AP4_CttsTableEntry))`  
  - 32-bit: `0x20000001 × 8 = 0` (wrap) → tiny alloc → SetItemCount constructs 0x20000001 items into tiny heap block → **heap buffer overflow**
  - 64-bit: 4GB+ alloc → `std::bad_alloc` → crash (DoS)
- `new unsigned char[entry_count*8]`: `entry_count×8` is uint32 arithmetic; entry_count≥0x20000000 wraps to tiny value → underallocated buffer
- Loop reads `buffer[i*8]` for i<entry_count → heap OOB read from underallocated buffer

**Group 2 analysis — stz2 (Ap4Stz2Atom.cpp:89-119)**

- No bounds check on `sample_count` before `SetItemCount`
- `table_size = (sample_count * m_FieldSize + 7) / 8`: computed in uint32 arithmetic; with `m_FieldSize=16` and `sample_count=0x10000001`: `0x10000001×16 = 0x100000010 → 0x10` (wrap), `table_size = 2`
- Size check `(table_size+8) > size` → `10 > size` → passes for any box >10 bytes — **check bypassed**
- `new unsigned char[2]` → 2-byte buffer
- Loop `m_Entries[i] = AP4_BytesToUInt16BE(&buffer[i*2])` for i=0..sample_count-1 → reads heap past end of 2-byte buffer → **heap OOB read**

**Group 3 analysis — trun (Ap4TrunAtom.cpp:127)**

- No bounds check on `sample_count` before `SetItemCount(sample_count)` 
- Same root cause as ctts: arbitrary large sample_count → integer overflow (32-bit) or crash (64-bit)
- `sizeof(TrunAtom::Entry) = 16` bytes → on 32-bit: `0x10000001×16 = 0x100000010 → 0x10=16` byte alloc → SetItemCount writes 256M entries → **heap buffer overflow**

## VULN: ctts entry_count unbounded → heap overflow (32-bit) / DoS (64-bit)
- **漏洞类别**: memory-safety
- **函数**: AP4_CttsAtom::AP4_CttsAtom()
- **行号**: 77-98
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: main() → AP4_File::AP4_File() → AP4_AtomFactory::CreateAtomFromStream() → AP4_CttsAtom::Create() → AP4_CttsAtom::AP4_CttsAtom(size, version, flags, stream)
- **描述**: ctts 构造函数在从流读取 entry_count 后，直接调用 `m_Entries.SetItemCount(entry_count)`，没有像 stco/stsz 那样先对 entry_count 做上界校验（比较 (size - header) / 8）。在 32-bit 平台上，`EnsureCapacity(entry_count)` 内部计算 `count * sizeof(AP4_CttsTableEntry)` = `entry_count × 8`，当 entry_count ≥ 0x20000001 时，该乘法在 32-bit unsigned 算术中发生整数溢出（`0x20000001 × 8 = 0x100000008` → 截断为 8），导致 `::operator new(8)` 仅分配 8 字节，而 SetItemCount 随后对 `m_Items[0..entry_count-1]` 全部写入默认构造的 AP4_CttsTableEntry（8 字节/条），造成严重的堆缓冲区溢出（heap buffer overflow）。在 64-bit 平台上，4 GB+ 的分配导致 `std::bad_alloc` 抛出，进程崩溃（DoS）。此外，即便在 64-bit 上 SetItemCount 成功（大内存场景），后续 `new unsigned char[entry_count*8]` 也因同一 32-bit 整数溢出得到一个极小的 buffer，循环 `m_Entries[i] = AP4_BytesToUInt32BE(&buffer[i*8])` 对每个 i≥1 均读越界堆内存（heap OOB read）。
- **触发条件**: 在 MP4 文件的 moov/trak/mdia/minf/stbl 中嵌入一个 ctts box（即使 box size 只有 20 字节），将 entry_count 字段设为 0x20000001（或类似可触发溢出的大值）。box size 只需满足 factory 的 `size > bytes_available` 检查，无需文件庞大。
- **安全影响**: 32-bit 平台下：大量写入至堆越界区域（约 4 GB 写操作至 8 字节分配块），覆盖堆管理结构和相邻对象，攻击者在进行堆布局（heap grooming）后可实现任意代码执行（RCE）。64-bit 平台下：进程立即因 std::bad_alloc 崩溃（DoS）。

## VULN: stz2 table_size integer overflow bypasses size check → heap OOB read
- **漏洞类别**: memory-safety
- **函数**: AP4_Stz2Atom::AP4_Stz2Atom()
- **行号**: 89-120
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-126 (Buffer Over-read)
- **CVSS v3.1**: 7.1 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: main() → AP4_File::AP4_File() → AP4_AtomFactory::CreateAtomFromStream() → AP4_Stz2Atom::Create() → AP4_Stz2Atom::AP4_Stz2Atom(size, version, flags, stream)
- **描述**: stz2 构造函数读取 sample_count（来自文件字段）后，直接调用 `m_Entries.SetItemCount(sample_count)` 且无任何前置上界校验。随后计算 `table_size = (sample_count * m_FieldSize + 7) / 8`，其中乘法 `sample_count * m_FieldSize` 在 unsigned int（32-bit）算术中进行。当 `m_FieldSize = 16`（合法值）且 `sample_count = 0x10000001` 时，`0x10000001 × 16 = 0x100000010` 在 32-bit 溢出截断为 `0x10 = 16`，导致 `table_size = (16+7)/8 = 2`（只有 2 字节）。随后的大小校验 `(table_size + 8) > size` 计算为 `10 > size`，对任何正常 box size（均 >10）的校验失败，保护措施被绕过。代码分配仅 2 字节的 `buffer`，并读取 2 字节。接着循环 `for (unsigned int i=0; i<0x10000001; i++) m_Entries[i] = AP4_BytesToUInt16BE(&buffer[i*2])` 对 i≥1 时访问 `buffer[2]`、`buffer[4]`……等越界位置，连续读取堆内存中 buffer 之后的区域（读取量约 512 MB），并将这些值写入 m_Entries 数组，造成堆越界读取（heap buffer over-read）与数据污染。
- **触发条件**: 在 MP4 文件的 stbl 中嵌入 stz2 box，将 field_size 字段设为 16（有效值），将 sample_count 设为 0x10000001 或任何满足 `sample_count * 16` 在 32-bit 整数溢出的值（≥ 0x10000000）。前提：目标系统有足量 RAM（≥1 GB）以使 SetItemCount 的 1 GB 分配成功；否则触发 DoS。
- **安全影响**: 在拥有足量 RAM 的系统上：程序从 buffer 后的堆内存中大量越界读取（信息泄露，可能暴露敏感地址或数据），读取结果被存入 m_Entries，导致后续样本大小数据被污染，可能引发后续的越界访问或被用于进一步利用。内存不足时进程崩溃（DoS）。

## VULN: trun sample_count unbounded → heap overflow (32-bit) / DoS (64-bit)
- **漏洞类别**: memory-safety
- **函数**: AP4_TrunAtom::AP4_TrunAtom()
- **行号**: 104-151
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: main() → AP4_File::AP4_File() → AP4_AtomFactory::CreateAtomFromStream() → AP4_TrunAtom::Create() → AP4_TrunAtom::AP4_TrunAtom(size, version, flags, stream)
- **描述**: trun 构造函数读取 `sample_count`（AP4_UI32，来自文件字段）后，未做任何上界校验直接调用 `m_Entries.SetItemCount(sample_count)`（第 127 行）。AP4_TrunAtom::Entry 结构体含 4 个 AP4_UI32 字段，sizeof = 16 字节。在 32-bit 平台上，`EnsureCapacity(sample_count)` 计算 `sample_count × sizeof(Entry) = sample_count × 16`：当 `sample_count = 0x10000001` 时，`0x10000001 × 16 = 0x100000010` 在 32-bit unsigned 算术中截断为 `0x10 = 16`，导致 `::operator new(16)` 仅分配 16 字节，但 SetItemCount 继续对 `m_Items[0..0x10000000]` 每条写入 16 字节的 Entry 对象（默认构造），造成大量写入越界的堆缓冲区溢出（heap buffer overflow）。在 64-bit 平台上，`::operator new(0x10000001 × 16 = 0x100000010 ≈ 4 GB)` 导致 `std::bad_alloc`，进程崩溃。即便 mp42aac 主逻辑不直接使用 trun 数据，`new AP4_File(*input)` 在解析顶层原子时仍会解析 moof/traf/trun，该漏洞在解析阶段即被触发。
- **触发条件**: 在 MP4 文件的 moof/traf 下嵌入 trun box（fragmented MP4 结构），将 sample_count 设为 0x10000001 或任何使 `sample_count × 16` 在 32-bit 整数溢出的值（≥ 0x10000000）。trun box 可以体积极小（仅声明极小的 box size），无需文件体积庞大。
- **安全影响**: 32-bit 平台下：约 4 GB 的写操作指向仅 16 字节的堆分配块，大量覆盖堆管理元数据和相邻对象，攻击者通过堆布局可实现任意代码执行（RCE）。64-bit 平台下：进程因 std::bad_alloc 崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
