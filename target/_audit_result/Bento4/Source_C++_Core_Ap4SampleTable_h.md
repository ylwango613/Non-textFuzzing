I have all the information needed. Let me do one final verification on the ctts bounds check comparison with other atoms.

**Group 1 analysis (Ap4CttsAtom.cpp:77–97):** `entry_count` is read directly from stream with no bounds check (`m_SampleCount > (size-8)/4` in stsz; `m_EntryCount > (size-AP4_FULL_ATOM_HEADER_SIZE-4)/4` in stco; `(size - AP4_ATOM_HEADER_SIZE - 4)/12 < entry_count` in stsc) — ctts has **none** of these. Then `new unsigned char[entry_count*8]`: on 32-bit, `entry_count*8` is a 32-bit multiplication. When entry_count ≥ 0x20000000, this overflows to a small value. Before that, `m_Entries.SetItemCount(entry_count)` calls `EnsureCapacity(entry_count)` which computes `count*sizeof(AP4_CttsTableEntry)` = `count*8`; on 32-bit this is also 32-bit and overflows, allocating only 8 bytes. The constructor loop then writes entry_count items into 8 bytes — heap overflow.

**Group 2 analysis (Ap4Stz2Atom.cpp:88–95):** `unsigned int table_size = (sample_count*m_FieldSize+7)/8` — both `sample_count` (AP4_UI32) and `m_FieldSize` (AP4_UI08, max 16) are 32-bit operands. For field_size=8 and sample_count=0x40000000: `0x40000000*8 = 0x200000000 → 32-bit wrap to 0`, table_size=0. The check `(0+8) > size` passes for size≥9. `new unsigned char[0]`, `stream.Read(buffer, 0)` reads nothing. The case-8 loop then reads `buffer[i]` for i=0..sample_count-1 — heap OOB. Also `m_Entries.SetItemCount(0x40000000)`: EnsureCapacity computes `0x40000000 * sizeof(AP4_UI32)` = `0x40000000 * 4` = `0x100000000 → 0` (32-bit wrap), 0-byte allocation, then overwrites adjacent heap in constructor loop.

**Group 3 analysis (Ap4StcoAtom.cpp:78–82):** `size - AP4_FULL_ATOM_HEADER_SIZE - 4` when `size` = 12 (minimum allowed by Create()'s check `size >= AP4_FULL_ATOM_HEADER_SIZE = 12`) evaluates as `12-12-4 = 0xFFFFFFFC` (unsigned underflow). `0xFFFFFFFC/4 = 0x3FFFFFFF` — m_EntryCount is then clamped to 0x3FFFFFFF → `new AP4_UI32[0x3FFFFFFF]` → 4 GB allocation → `std::bad_alloc` → crash.

## VULN: AP4_CttsAtom missing bounds-check + integer overflow → heap overflow (32-bit) / crash (64-bit)
- **漏洞类别**: memory-safety
- **函数**: AP4_CttsAtom::AP4_CttsAtom()
- **行号**: 77-97 (Ap4CttsAtom.cpp)
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → `new AP4_File(*input)` → AP4_Movie → AP4_Track → AP4_AtomSampleTable constructor → stbl child-atom parsing → `AP4_CttsAtom::Create()` → `new AP4_CttsAtom(size, version, flags, stream)` → integer overflow in EnsureCapacity / buffer allocation
- **描述**: `entry_count` 直接从 MP4 文件流读取（`stream.ReadUI32(entry_count)`），与 stsz/stco/stsc 等均有 `entry_count > (size - header - fields) / entry_bytes` 上界检查不同，ctts 完全没有此校验。随后 `m_Entries.SetItemCount(entry_count)` 调用 `EnsureCapacity(entry_count)`，在 **32 位平台**上计算 `count * sizeof(AP4_CttsTableEntry)` = `count * 8`：当 entry_count ≥ 0x20000000 时，该乘法产生 32 位回绕（例如 0x20000001 × 8 = 0x100000008 → 8），`::operator new(8)` 仅分配 8 字节，但 `m_AllocatedCount` 被设为 0x20000001；随后构造循环对 0x20000001 个 AP4_CttsTableEntry 执行 placement new，从第 2 个（偏移 8 字节）起即越出分配边界，造成堆溢出。同样，`new unsigned char[entry_count*8]` 的 32 位溢出使缓冲区为 8 字节，而后续 for 循环读 `buffer[i*8]`（i 从 0 到 entry_count-1）也产生堆越界读。64 位平台上 `count*sizeof(T)` 不溢出，导致数 GB 级别分配请求，触发 `std::bad_alloc`，进程崩溃（DoS）。
- **触发条件**: 在 MP4 文件的 moov/trak/mdia/minf/stbl 内嵌入一个 ctts box，其 entry_count 字段设为 ≥ 0x20000000（32 位溢出触发）；atom size 字段设置合法（≥ AP4_FULL_ATOM_HEADER_SIZE=12）即可绕过 Create() 检查。
- **安全影响**: 32 位目标：堆缓冲区溢出，可覆盖相邻堆块元数据及数据，具有远程代码执行潜力（RCE）。64 位目标：进程因 std::bad_alloc 崩溃，导致拒绝服务（DoS）。

## VULN: AP4_Stz2Atom table_size integer overflow → under-allocated buffer → heap OOB read/write (32-bit)
- **漏洞类别**: memory-safety
- **函数**: AP4_Stz2Atom::AP4_Stz2Atom()
- **行号**: 88-121 (Ap4Stz2Atom.cpp)
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → `new AP4_File(*input)` → AP4_AtomSampleTable constructor → stbl child-atom parsing → `AP4_Stz2Atom::Create()` → `new AP4_Stz2Atom(size, version, flags, stream)` → integer overflow in table_size calculation
- **描述**: 第 90 行 `unsigned int table_size = (sample_count*m_FieldSize+7)/8`：`sample_count`（AP4_UI32）与 `m_FieldSize`（AP4_UI08，有效值 4/8/16）的乘积在 **32 位平台**为 32 位无符号运算。以 field_size=8、sample_count=0x40000000 为例：`0x40000000 × 8 = 0x200000000` 回绕为 0，`table_size = (0+7)/8 = 0`。随后的上界检查 `if ((table_size+8) > size) return;` 仅需 atom size ≥ 9 即可通过，`new unsigned char[0]` 成功分配微型缓冲区，`stream.Read(buffer, 0)` 不读取任何数据。此后 `case 8` 分支循环 `m_Entries[i] = buffer[i]`（i 从 0 到 sample_count-1），`buffer[i]` 从 i=1 起越界读取相邻堆内容。同时，`m_Entries.SetItemCount(0x40000000)` 调用 `EnsureCapacity(0x40000000)`，在 32 位平台计算 `0x40000000 × sizeof(AP4_UI32) = 0x100000000 → 0`，分配 0 字节；构造循环从 `m_Items[1]` 起即造成堆越界写。64 位平台 table_size 乘法不溢出，巨量分配导致 bad_alloc / DoS。
- **触发条件**: 在 stbl 内嵌入 stz2 box（替代 stsz），设置 field_size=8，sample_count ≥ 0x40000000（或 field_size=16，sample_count ≥ 0x20000000）；atom size 设置充分大（≥ 9）以绕过 table_size 上界检查。
- **安全影响**: 32 位目标：堆缓冲区越界写（写入相邻堆块），同时堆越界读将堆内存内容写入 m_Entries，具有 RCE 潜力。64 位目标：DoS（std::bad_alloc 崩溃）。

## VULN: AP4_StcoAtom bounds-check integer underflow → DoS via extreme allocation
- **漏洞类别**: memory-safety
- **函数**: AP4_StcoAtom::AP4_StcoAtom()
- **行号**: 78-82 (Ap4StcoAtom.cpp)
- **CWE**: CWE-191 (Integer Underflow) → CWE-400 (Uncontrolled Resource Consumption)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → `new AP4_File(*input)` → AP4_AtomSampleTable constructor → stbl child-atom parsing → `AP4_StcoAtom::Create()` → `new AP4_StcoAtom(size, version, flags, stream)` → underflow in clamping expression
- **描述**: `Create()` 仅检查 `size >= AP4_FULL_ATOM_HEADER_SIZE`（=12），允许 size=12~15 的 stco box 通过。进入构造函数后，第 78~79 行的上界钳位表达式 `(size - AP4_FULL_ATOM_HEADER_SIZE - 4) / 4`：当 size=12 时，`12 - 12 - 4 = 0xFFFFFFFC`（AP4_UI32 无符号下溢），除以 4 得 0x3FFFFFFF（约 10 亿）。无论文件字段 `m_EntryCount` 取何值（≤ 0xFFFFFFFF > 0x3FFFFFFF 时均会被钳位为 0x3FFFFFFF），随后 `new AP4_UI32[0x3FFFFFFF]` 尝试申请约 4 GB 内存，以及 `new unsigned char[m_EntryCount*4]` 同样尝试 4 GB 申请，触发 `std::bad_alloc`，进程立即崩溃。
- **触发条件**: 将 MP4 文件中 stco atom 的 box size 字段设为 12（合法最小值，仅含 size+type+version/flags 共 12 字节，不含 entry_count 字段空间）。
- **安全影响**: 所有平台均可稳定触发进程崩溃（DoS）；处理用户上传 MP4 文件的服务若受此影响，可被远程利用进行拒绝服务攻击。

<!-- AUDIT_PROMPT_VERSION: 1 -->
