I now have a complete picture of all the vulnerabilities. Let me compile the final audit report.

## VULN: AP4_CttsAtom – Integer overflow in `entry_count*8` → unbounded allocation, heap OOB write (32-bit)
- **漏洞类别**: memory-safety
- **函数**: AP4_CttsAtom::AP4_CttsAtom()
- **行号**: 77-97
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 7.8 (AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac input.mp4 → AP4_File::AP4_File() → AP4_AtomFactory::CreateAtomsFromStream() → CreateAtomFromStream() → AP4_CttsAtom::Create(size_32, stream) → new AP4_CttsAtom(size, version, flags, stream)
- **描述**: Ap4CttsAtom.cpp 第77–97行，`entry_count` 直接从文件字段读取，**完全没有上界校验**（对比 StcoAtom、StszAtom 均有 `if (count > (size-hdr)/stride)` 防护，CttsAtom 缺失）。随后第80行 `new unsigned char[entry_count*8]`：`entry_count`（AP4_UI32）与整数字面量 `8`（int，被提升为 unsigned int）相乘，结果类型为 32-bit `unsigned int`，当 `entry_count ≥ 0x20000000` 时乘积溢出到极小值（如 0 或 8）。在 32-bit 构建中，第79行 `m_Entries.SetItemCount(entry_count)` 内部 `EnsureCapacity` 调用 `::operator new(entry_count * sizeof(AP4_CttsTableEntry))` 同样溢出（如 `0x20000001 * 8 = 8`），导致 `m_Items` 只有 8 字节；随后 SetItemCount 的 placement-new 循环在 `m_Items[1]` 即已越界写堆。继而第88–96行 for 循环对 `m_Entries[i]` 的连续写入构成经典堆缓冲区溢出。在 64-bit 构建中，EnsureCapacity 用 `size_t` 正确计算（~4 GB），抛出 `std::bad_alloc`，程序无 catch → crash（DoS）。
- **触发条件**: 构造包含 `ctts` box 的 MP4，box size 字段合法（如 0x1C），但 `entry_count` 字段设为 `0x20000001`（0x80000000 以上任意值均可触发溢出）。该 box 置于 `moov→trak→mdia→minf→stbl` 路径下，mp42aac 正常解析时必经此路径。
- **安全影响**: 32-bit 目标上堆内存破坏，攻击者可能通过覆盖堆元数据实现任意代码执行（RCE）；64-bit 目标上程序崩溃（DoS）。

## VULN: AP4_SbgpAtom – Integer overflow in bounds-check expression `entry_count*8` → check bypassed → heap OOB
- **漏洞类别**: memory-safety
- **函数**: AP4_SbgpAtom::AP4_SbgpAtom()
- **行号**: 83-96
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 7.8 (AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac input.mp4 → AP4_AtomFactory::CreateAtomFromStream() → AP4_SbgpAtom::Create(size, stream) → new AP4_SbgpAtom(size, version, flags, stream)
- **描述**: Ap4SbgpAtom.cpp 第87行存在整数溢出绕过边界检查：`if (remains < entry_count*8)` 中 `entry_count`（AP4_UI32）与 `8`（int，提升为 unsigned int）做 32-bit 乘法，当 `entry_count = 0x20000000` 时乘积回绕为 0（`unsigned int`），使得条件变为 `remains < 0U`，在无符号语义下恒为 false，防护失效。随后第90行 `m_Entries.SetItemCount(entry_count)` 以不受限的超大计数执行，在 32-bit 构建中 `EnsureCapacity` 内 `::operator new(0x20000000 * 8)` 溢出为 0，返回极小分配，`m_Items` 只有 0 字节可用；紧接着 SetItemCount 的 placement-new 循环和第91–96行 for 循环对 `m_Entries[i]` 的访问均构成堆越界写。
- **触发条件**: MP4 文件中 `moov/trak/mdia/minf/stbl/sbgp` 或 `moof/traf/sbgp` box 的 `entry_count` 字段设为 ≥ 0x20000000 的值（如 0x20000000）即可触发整数溢出使防护失效。
- **安全影响**: 32-bit 目标堆内存破坏，可能实现 RCE；64-bit 目标抛出 `std::bad_alloc`（DoS）。

## VULN: AP4_SaioAtom – Integer overflow in bounds-check `entry_count*(version==0?4:8)` → check bypassed → heap OOB
- **漏洞类别**: memory-safety
- **函数**: AP4_SaioAtom::AP4_SaioAtom()
- **行号**: 106-126
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 7.8 (AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac input.mp4 → AP4_AtomFactory::CreateAtomFromStream() → AP4_SaioAtom::Create(size, stream) → new AP4_SaioAtom(size, version, flags, stream)
- **描述**: Ap4SaioAtom.cpp 第110行 `if (remains < entry_count*(m_Version==0?4:8))` 同样受整数溢出影响：version=1 时因子为 8，`entry_count = 0x20000000` 时乘积回绕为 0（32-bit unsigned），边界检查恒为 false 而被绕过；version=0 时因子为 4，溢出阈值为 `entry_count ≥ 0x40000000`。两种情况下随后第113行 `m_Entries.SetItemCount(entry_count)` 及第114–126行循环对 `m_Entries[i]` 写入均在堆越界区域执行（32-bit），或触发 `std::bad_alloc`（64-bit DoS）。
- **触发条件**: MP4 中 `saio` box（可出现于 `moov/trak/mdia/minf/stbl/saio` 或 `moof/traf/saio`）设 version=1、`entry_count = 0x20000000`，或 version=0、`entry_count = 0x40000000`。
- **安全影响**: 32-bit 目标堆内存破坏（潜在 RCE）；64-bit 目标崩溃（DoS）。

## VULN: AP4_TrunAtom – No bounds check on file-controlled `sample_count` → unbounded SetItemCount → heap OOB
- **漏洞类别**: memory-safety
- **函数**: AP4_TrunAtom::AP4_TrunAtom()
- **行号**: 104-151
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 7.8 (AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac input.mp4 → AP4_AtomFactory::CreateAtomFromStream() (in context moof/traf) → AP4_TrunAtom::Create(size, stream) → new AP4_TrunAtom(size, version, flags, stream)
- **描述**: Ap4TrunAtom.cpp 第104–105行从 MP4 文件直接读取 `sample_count`（AP4_UI32）并在无任何上界校验的情况下第127行调用 `m_Entries.SetItemCount(sample_count)`。`AP4_TrunAtom::Entry` 结构含4个 AP4_UI32 字段，`sizeof(Entry)=16`（0x10）字节。在 32-bit 构建中，当 `sample_count ≥ 0x10000000` 时 `EnsureCapacity` 内 `::operator new(sample_count * 16)` 溢出（如 `0x10000001 * 16 = 16` bytes），`m_Items` 只有16字节（1个 Entry）；但随后 SetItemCount 的 placement-new 循环即在 `m_Items[1]` 处越界写堆，接下来第128–151行 for 循环 `stream.ReadUI32(m_Entries[i].sample_duration)` 等每次写都越界，连续破坏堆内存。在 64-bit 构建中，巨型分配触发 `std::bad_alloc`（DoS）。
- **触发条件**: 分片 MP4（fragmented MP4）中 `moof→traf→trun` box 的 `sample_count` 字段设为 ≥ 0x10000000（32-bit溢出阈值），flags 字段设置至少1个样本字段存在位（如 sample_size_present）。mp42aac 通过 AP4_Movie 解析 moof 时会触发此路径。
- **安全影响**: 32-bit 目标堆内存破坏，可能实现 RCE；64-bit DoS。

## VULN: AP4_TfraAtom – No bounds check on file-controlled `entry_count` → unbounded SetItemCount → heap OOB
- **漏洞类别**: memory-safety
- **函数**: AP4_TfraAtom::AP4_TfraAtom()
- **行号**: 86-181
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 7.5 (AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac input.mp4 → AP4_AtomFactory::CreateAtomFromStream() → AP4_TfraAtom::Create(size, stream) → new AP4_TfraAtom(size, version, flags, stream)
- **描述**: Ap4TfraAtom.cpp 第86–88行从文件读取 `entry_count`（AP4_UI32）后直接调用 `m_Entries.SetItemCount(entry_count)`，无上界验证。`AP4_TfraAtom::Entry` 含 m_Time(UI64)、m_MoofOffset(UI64)、m_TrafNumber(UI32)、m_TrunNumber(UI32)、m_SampleNumber(UI32)，在64-bit上约占32字节（含对齐）。在 32-bit 构建中，当 `entry_count * sizeof(Entry)` 在 32-bit 乘法中溢出时，`EnsureCapacity` 分配极小缓冲区；随后 SetItemCount 的 placement-new 循环和第89–181行 for 循环（每次调用 ReadUI64/ReadUI32 并写入 `m_Entries[i].m_Time` 等字段）在越界区域执行堆写入，造成堆内存破坏。
- **触发条件**: MP4 文件 `mfra→tfra` box（Movie Fragment Random Access box）中 `entry_count` 字段设为可触发溢出的超大值（依 sizeof(Entry) 不同，阈值在 0x8000000~0x20000000 之间）。mp42aac 在解析 mfra 区域时会触发此路径。
- **安全影响**: 32-bit 目标堆内存破坏（潜在 RCE）；64-bit `std::bad_alloc` 崩溃（DoS）。

## VULN: AP4_StcoAtom – Unsigned integer underflow in bounds check when atom size<16 → inflated entry cap → OOM DoS
- **漏洞类别**: memory-safety
- **函数**: AP4_StcoAtom::AP4_StcoAtom()
- **行号**: 77-92
- **CWE**: CWE-191 (Integer Underflow)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac input.mp4 → AP4_AtomFactory::CreateAtomFromStream() → AP4_StcoAtom::Create(size_32, stream) → new AP4_StcoAtom(size, version, flags, stream)
- **描述**: Ap4StcoAtom.cpp 第78–79行上界收紧计算 `(size - AP4_FULL_ATOM_HEADER_SIZE - 4) / 4`，其中 `AP4_FULL_ATOM_HEADER_SIZE=12`，减数为 16。当 atom size 在 [12,15] 之间（可通过 Create 中 `size < AP4_FULL_ATOM_HEADER_SIZE` 即 12 的检查，但仍 < 16）时，`size - 12 - 4 = size - 16` 在 `AP4_UI32` 无符号减法中产生下溢（如 size=12 → `0xFFFFFFFC`），导致 cap 被错误地设置为约 `0x3FFFFFFF`（10亿）。攻击者在文件中将 `m_EntryCount` 设为任意大值（如 0x10000000），可绕过本应拒绝该值的防护。第81行 `new AP4_UI32[m_EntryCount]` 和第82行 `new unsigned char[m_EntryCount*4]` 尝试分配数 GB 内存，程序因 `std::bad_alloc` 崩溃（DoS）。
- **触发条件**: 构造 `stco` box，size 字段设为 12–15（合法 MP4 box 最小结构），`entry_count` 字段设为大值（如 0x10000000）。mp42aac 解析 `moov→trak→mdia→minf→stbl→stco` 时触发。
- **安全影响**: 程序因内存耗尽（`std::bad_alloc`）崩溃，拒绝服务（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
