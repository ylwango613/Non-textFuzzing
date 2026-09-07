## VULN: Ap4CttsAtom.cpp — ctts entry_count 整数溢出导致堆缓冲区越界写

- **漏洞类别**: 整数溢出 → 堆缓冲区溢出（Integer Overflow → Heap-based Buffer Overflow）
- **函数**: `AP4_CttsAtom::AP4_CttsAtom(AP4_UI32, AP4_ByteStream&)`
- **行号**: Ap4CttsAtom.cpp:77–97（关键语句在第 79、80 行）
- **CWE**: CWE-190 (Integer Overflow or Wraparound)，继发 CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H = **7.8 (High)**
- **严重程度**: High（32 位构建可导致 RCE；64 位构建导致 DoS）
- **攻击向量**: 攻击者提供一个合法结构的 MP4 文件，其中 stbl 子树包含一个 size=16 字节的 ctts 全量 box（12 字节 full-atom 头 + 4 字节 entry_count 字段），entry_count 字段值设为 0x20000001
- **外部触发路径**: `mp42aac crafted.mp4 out.aac` → `new AP4_File(*input)` → `AP4_AtomFactory::CreateAtomFromStream` → `AP4_CttsAtom::Create` → `AP4_CttsAtom::AP4_CttsAtom`（文件解析阶段，无需成功读取任何音频样本）
- **描述**: 构造函数在第 77 行无验证地读取 `entry_count`（`AP4_UI32`，32 位无符号整数），既不校验其是否超出 box 可用字节数，也不检测后续乘法是否溢出。第 79 行 `m_Entries.SetItemCount(entry_count)` 调用 `EnsureCapacity`，在 32 位平台上计算 `entry_count * sizeof(AP4_CttsTableEntry)` = `0x20000001 * 8`，结果溢出为 8，仅分配 8 字节；`SetItemCount` 内部对 0x20000001 个元素执行 placement-new 循环，立即从第 2 次迭代起发生大规模堆外写。第 80 行 `new unsigned char[entry_count*8]` 同样溢出，分配 8 字节，与 m_Items 一起成为过小的目标。在 64 位平台上，EnsureCapacity 中 `count * sizeof(T)` 以 size_t（64 位）计算，产生约 4 GB 的分配请求，触发 `std::bad_alloc`，进程崩溃。
- **触发条件**: 构造一个 MP4 文件，使 moov/trak/mdia/minf/stbl/ctts box 的 size=16（或任意合法大小），entry_count=0x20000001（或任意满足 `entry_count * 8` mod 2^32 结果 < 实际数据量的值）。该 box 将通过工厂层的 `size ≥ 8` 合法性检查并进入构造函数。
- **安全影响**: 32 位构建：堆内存在 SetItemCount 内部被大面积覆写，攻击者可通过堆风水（heap feng shui）实现任意代码执行（RCE）。64 位构建：`std::bad_alloc` 未被捕获，`std::terminate` 终止进程，导致拒绝服务（DoS）。

## VULN: Ap4Stz2Atom.cpp — stz2 sample_count 整数溢出导致堆缓冲区越界写

- **漏洞类别**: 整数溢出 → 堆缓冲区溢出（Integer Overflow → Heap-based Buffer Overflow）
- **函数**: `AP4_Stz2Atom::AP4_Stz2Atom(AP4_UI32, AP4_UI08, AP4_UI32, AP4_ByteStream&)`
- **行号**: Ap4Stz2Atom.cpp:88–119（关键语句在第 88–91 行）
- **CWE**: CWE-190 (Integer Overflow or Wraparound)，继发 CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H = **7.8 (High)**
- **严重程度**: High
- **攻击向量**: 攻击者提供一个 MP4 文件，其中 stbl 包含 stz2 box，field_size=8，sample_count=0x20000001
- **外部触发路径**: `mp42aac crafted.mp4 out.aac` → `new AP4_File(*input)` → `AP4_AtomFactory::CreateAtomFromStream` → `AP4_Stz2Atom::Create` → `AP4_Stz2Atom::AP4_Stz2Atom`
- **描述**: 第 88 行无条件调用 `m_Entries.SetItemCount(sample_count)`，此时既未验证 sample_count 与 box 剩余字节的关系，也未进行整数溢出检查。对于 field_size=8、sample_count=0x20000001，在 32 位平台上 `EnsureCapacity` 中 `0x20000001 * sizeof(AP4_UI08)` = `0x20000001 * 1` = 1（另一种情形下溢出取决于元素类型），但 sample_count 过大本身足以让 placement-new 循环写出界。对于 AP4_Array<AP4_UI08>（1 字节元素）：`EnsureCapacity(0x20000001)` 分配 `0x20000001 * 1 = 0x20000001` 字节；若系统允许（或 overcommit），则 SetItemCount 中 placement-new 循环正常；但后续第 89 行 `table_size = (0x20000001 * 8 + 7) / 8`（32 位乘法溢出）= `(8 + 7) / 8` = 1，仅分配 1 字节的 buffer，而第 114-115 行循环以 sample_count=0x20000001 次访问 `buffer[i]`（m_FieldSize==8 分支），从第 2 次迭代起越界读写。在 field_size ≥ 4 且 sample_count 使乘积溢出时，第 90 行大小检查 `(table_size+8) > size`（正确常量应为 `table_size + 20 + AP4_FULL_ATOM_HEADER_SIZE > size`）因 table_size 被截断为小值而失效，不能阻止后续越界。在 64 位平台，SetItemCount 分配 `(size_t)sample_count * sizeof(T)` = 0x20000001 字节或 4 GB+，可能 bad_alloc 崩溃。
- **触发条件**: stz2 box 的 field_size=8（或 4/16）且 sample_count=0x20000001，此时 table_size 溢出为极小值，size 检查无法拦截，随后循环以 sample_count 次迭代访问过小的 buffer。
- **安全影响**: 32 位构建：堆越界写，可导致 RCE。64 位构建：DoS（std::bad_alloc）或堆越界读（如 overcommit 使 SetItemCount 成功但 buffer 仅 1 字节时循环 OOB 读 buffer）。

## VULN: Ap4StscAtom.cpp — stsc bounds 检查使用错误头部常量导致越界读取相邻 box 数据

- **漏洞类别**: 越界读（OOB Read — 错误 header 常量导致 box 边界跨越）
- **函数**: `AP4_StscAtom::AP4_StscAtom(AP4_UI32, AP4_ByteStream&)`
- **行号**: Ap4StscAtom.cpp:75–85（关键错误在第 75、77 行）
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N = **4.4 (Medium)**
- **严重程度**: Medium
- **攻击向量**: 攻击者构造 stsc box（full atom），size 字段设置为一个使 `(size-8-4)/12 >= 1` 成立、但实际可用字节不足 12 的值（如 size=24，entry_count=1）
- **外部触发路径**: `mp42aac crafted.mp4 out.aac` → `new AP4_File(*input)` → `AP4_AtomFactory::CreateAtomFromStream` → `AP4_StscAtom::Create` → `AP4_StscAtom::AP4_StscAtom`
- **描述**: stsc 是 full atom（版本+标志占 4 字节），正确的有效载荷起始偏移为 `AP4_FULL_ATOM_HEADER_SIZE = 12`。但第 75 行初步检查和第 77 行 entry_count 上界检查均使用 `AP4_ATOM_HEADER_SIZE = 8`，比正确值少 4 字节。以 size=24、entry_count=1 为例：合法检查应为 `(24-12-4)/12 = 0 < 1`，应拒绝；实际检查 `(24-8-4)/12 = 1 >= 1`，通过。随后分配 `new unsigned char[12]`（正确大小），调用 `stream.Read(buffer, 12)`：stsc box 内 full-atom 头之后的可用字节为 `24-12-4 = 8`（entry_count 字段 4 字节已消耗），仅 8 字节在 stsc box 内，读取 12 字节时额外读取 4 字节来自下一个 box（通常为下一个 stbl 子 box 的前 4 字节——其 size 字段）。这 4 字节被解析为 stsc 表项的 `sample_description_index`，导致后续 `GetSampleForChunk` 返回攻击者控制的 desc 值，`sample.SetDescriptionIndex(desc-1)` 若 desc=0 则产生无符号下溢（0xFFFFFFFF）。
- **触发条件**: stsc box 中 `size - 12 - 4`（正确剩余字节）< `entry_count * 12`，但 `size - 8 - 4`（错误剩余字节）>= `entry_count * 12`，差值最多 4 字节。
- **安全影响**: 解析器读取相邻 box 的头部字节（攻击者完全控制）作为 stsc 表数据，可使 sample_description_index 被设为任意值；若调用者未验证该索引即用于数组访问（如 `GetSampleDescription(desc-1)` 在 desc=0 时），可导致越界数组访问或信息泄露。

## VULN: Ap4StssAtom.cpp — stss bounds 检查使用错误头部常量导致越界读取相邻 box 数据

- **漏洞类别**: 越界读（OOB Read — 错误 header 常量导致 box 边界跨越）
- **函数**: `AP4_StssAtom::AP4_StssAtom(AP4_UI32, AP4_ByteStream&)`
- **行号**: Ap4StssAtom.cpp:73–82（关键错误在第 73、78 行）
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N = **3.3 (Low)**
- **严重程度**: Low
- **攻击向量**: 攻击者构造 stss box，size=16，entry_count=1（full atom 头 12 字节 + entry_count 字段 4 字节 = 16，box 内无有效 entry 字节，但错误检查允许 entry_count=1）
- **外部触发路径**: `mp42aac crafted.mp4 out.aac` → `new AP4_File(*input)` → `AP4_AtomFactory::CreateAtomFromStream` → `AP4_StssAtom::Create` → `AP4_StssAtom::AP4_StssAtom`
- **描述**: 与 stsc 相同的根本错误：stss 同为 full atom（AP4_FULL_ATOM_HEADER_SIZE=12），但第 73 行 `if (size - AP4_ATOM_HEADER_SIZE < 4) return;` 及第 78 行 `if ((size - AP4_ATOM_HEADER_SIZE - 4) / 4 < entry_count) return;` 均使用 `AP4_ATOM_HEADER_SIZE = 8` 而非 12。以 size=16、entry_count=1 为例：正确检查 `(16-12-4)/4 = 0 < 1`，应拒绝；实际检查 `(16-8-4)/4 = 1 >= 1`，通过。随后 `new unsigned char[4]`（4 字节），`stream.Read(buffer, 4)` 从 box 之后读取 4 字节（stss box 内 full-atom 头后无剩余内容），这 4 字节来自下一个 box 的起始处。读取的值被放入 m_Entries[0] 并用作同步帧编号（sync sample number），使 `IsSampleSync()` 返回错误结果。
- **触发条件**: stss box 满足 `size - 16 < entry_count * 4`（正确检查应拒绝），但 `size - 12 >= entry_count * 4`（错误检查放行），即 box 实际可用字节比所需少 4 字节以内。
- **安全影响**: 解析器从相邻 box 的头部读取 4 字节作为 sync sample 编号；若后续代码将该值用作 `m_Entries[]` 无边界检查的索引（`AP4_Array::operator[]` 无边界检查），且写操作发生，则存在潜在堆写越界，具体影响取决于调用路径；在 mp42aac 直接路径下限于逻辑错误（帧同步判断错误），但在库的其他工具中可放大为内存安全问题。

<!-- AUDIT_PROMPT_VERSION: 1 -->
