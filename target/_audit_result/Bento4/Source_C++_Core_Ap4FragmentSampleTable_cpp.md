I have now read all relevant files. Let me compile my findings.

**Batch 1 summary (Ap4FragmentSampleTable.cpp):**
- Constructor (lines 56–93): accumulates `sample_count` from trun.GetEntries().ItemCount() (32-bit uint), calls `m_Samples.EnsureCapacity(sample_count)`.
- `AddTrun` (lines 107–231): line 120: `m_Samples.SetItemCount(start + trun->GetEntries().ItemCount())` — 32-bit arithmetic, no overflow guard; line 175: `m_Samples[start+i]` via unchecked `operator[]`.

**Batch 2 (Ap4TrunAtom.cpp):**
- Constructor line 127: `m_Entries.SetItemCount(sample_count)` where `sample_count` is read directly from the file with **no validation against the declared atom size**.

**Batch 3 (Ap4Array.h):**
- `EnsureCapacity` line 172: `::operator new(count * sizeof(T))` — on 32-bit, if `count * sizeof(T)` wraps to 0 (e.g., count = 0x10000000 with sizeof(Entry)=16 or count = 0x20000000 with sizeof(AP4_Sample)=40), a 0-byte allocation succeeds, but `m_AllocatedCount` is set to `count`. The subsequent `SetItemCount` construction loop then constructs objects at OOB positions.
- `operator[]` has **no bounds check**: `return m_Items[idx]`.

**Confirmed vulnerabilities:**

**VULN A**: Attacker sets trun `sample_count` = 0x20000000, no per-sample flags → `m_Entries.SetItemCount(0x20000000)`: `EnsureCapacity(0x20000000)` allocates `0x20000000×16 = 0` bytes on 32-bit (wrap-around), sets `m_AllocatedCount = 0x20000000`, loop body empty → no crash yet. Then `m_Samples.EnsureCapacity(0x20000000)`: allocates `0x20000000×40 = 0` bytes. Then `AddTrun` calls `m_Samples.SetItemCount(0x20000000)`: EnsureCapacity returns early (already "allocated"), then runs construction loop `new(&m_Items[i]) AP4_Sample()` for i=0..0x1FFFFFFF — **all OOB writes** into heap. The subsequent AddTrun inner loop (lines 173–226) then does `m_Samples[0+i]` via unchecked `operator[]` — further OOB reads/writes, setting sample sizes/offsets at arbitrary heap locations.

**VULN B**: Attacker sets trun `sample_count` = 0x10000000 with `AP4_TRUN_FLAG_SAMPLE_SIZE_PRESENT` set → `m_Entries.SetItemCount(0x10000000)`: 0-byte allocation. Then loop at Ap4TrunAtom.cpp:128–151 immediately calls `stream.ReadUI32(m_Entries[0].sample_size)` — **OOB write** at `m_Items[0]` in a 0-byte heap region.

## VULN: Integer overflow in AP4_Array::EnsureCapacity → heap buffer overflow in AP4_FragmentSampleTable::AddTrun (32-bit)
- **漏洞类别**: memory-safety
- **函数**: AP4_FragmentSampleTable::AddTrun() / AP4_FragmentSampleTable::AP4_FragmentSampleTable()
- **行号**: 67, 119-120, 173-215 (Ap4FragmentSampleTable.cpp); 166-185, 193-218 (Ap4Array.h)
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac input.mp4 → AP4_Movie::AP4_Movie → AP4_MovieFragment → AP4_ContainerAtom (traf) → AP4_FragmentSampleTable::AP4_FragmentSampleTable (constructor) → m_Samples.EnsureCapacity(sample_count) [Ap4FragmentSampleTable.cpp:67] → AP4_FragmentSampleTable::AddTrun → m_Samples.SetItemCount(start + trun->GetEntries().ItemCount()) [line 120] → AP4_Array<AP4_Sample>::SetItemCount → AP4_Array<AP4_Sample>::EnsureCapacity → ::operator new(count*sizeof(AP4_Sample)) [Ap4Array.h:172] → construction loop at m_Items[i] [Ap4Array.h:214]
- **描述**: 在 32-bit 编译目标上，`AP4_TrunAtom` 构造函数将来自 MP4 文件字段的 `sample_count`（AP4_UI32）直接传入 `m_Entries.SetItemCount(sample_count)`，后者调用 `EnsureCapacity(count)`。`EnsureCapacity` 执行 `::operator new(count * sizeof(T))`，在 32-bit 平台上 `count * sizeof(T)` 可发生整数环绕（例如 count=0x20000000，sizeof(AP4_TrunAtom::Entry)=16：0x20000000×16=0x200000000 mod 2^32=0），分配 0 字节但将 `m_AllocatedCount` 置为 count=0x20000000。trun 无 per-sample flag 时内部循环为空，不产生即时崩溃。随后 `AP4_FragmentSampleTable` 构造函数调用 `m_Samples.EnsureCapacity(0x20000000)`：sizeof(AP4_Sample)≈40 字节，0x20000000×40=0x500000000 mod 2^32=0，同样分配 0 字节但设 `m_AllocatedCount=0x20000000`。接着 `AddTrun` 调用 `m_Samples.SetItemCount(start + 0x20000000=0x20000000)`；`EnsureCapacity` 因 `count<=m_AllocatedCount` 提前返回，随即执行构造循环 `new((void*)&m_Items[i]) AP4_Sample()` for i=0..0x1FFFFFFF——`m_Items` 指向 0 字节分配，所有写操作均为堆越界写。后续 AddTrun 主循环（第 173–215 行）通过无边界检查的 `operator[]` 访问 `m_Samples[start+i]`，可向堆中任意偏移写入攻击者可控的 `sample_size`、`sample_offset`、`dts` 等字段值，造成任意堆内存破坏。
- **触发条件**: 构造一个包含 fragmented track 的 MP4 文件：moof→traf→trun，trun atom 中 `sample_count` = 0x20000000（约 537M），trun_flags = 0（无 per-sample 字段），trun atom body 仅约 24 字节。在 32-bit 编译的 mp42aac 上处理该文件即可触发。
- **安全影响**: 堆内存任意破坏，可覆盖相邻堆块元数据或对象指针；攻击者通过精心布局堆可将此漏洞升级为任意代码执行（RCE）。在 64-bit 系统上，`count*sizeof(T)` 不溢出，`::operator new` 抛出 `std::bad_alloc`（未捕获），进程崩溃，形成可靠 DoS。

## VULN: Unchecked trun sample_count causes integer overflow in EnsureCapacity → heap OOB write in AP4_TrunAtom constructor loop (32-bit)
- **漏洞类别**: memory-safety
- **函数**: AP4_TrunAtom::AP4_TrunAtom() (parsing constructor)
- **行号**: 104-151 (Ap4TrunAtom.cpp); 166-185 (Ap4Array.h)
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac input.mp4 → AP4_Movie → AP4_MovieFragment → AP4_ContainerAtom (traf) → AP4_TrunAtom::Create → AP4_TrunAtom::AP4_TrunAtom(size, version, flags, stream) → stream.ReadUI32(sample_count) → m_Entries.SetItemCount(sample_count) → AP4_Array<Entry>::EnsureCapacity(0x10000000) → ::operator new(0) → returns 0-byte ptr → loop: stream.ReadUI32(m_Entries[i].sample_size) → OOB write at m_Items[0]
- **描述**: `AP4_TrunAtom` 的流解析构造函数（Ap4TrunAtom.cpp:104–151）从 MP4 字节流直接读取 4 字节 `sample_count`，未与 atom 声明的 `size` 字段作任何交叉验证（即不检查 `sample_count * per_entry_bytes <= remaining_atom_bytes`）。之后调用 `m_Entries.SetItemCount(sample_count)` → `EnsureCapacity(sample_count)`：在 32-bit 平台，当 `sample_count=0x10000000`，`sizeof(Entry)=16` 时，`count*sizeof(T)=0x10000000*16=0x100000000 mod 2^32=0`，`::operator new(0)` 返回合法非空指针（0 字节分配），`m_AllocatedCount` 被设为 0x10000000，`m_ItemCount` 也被设为 0x10000000。随即进入 per-sample 字段解析循环（第 128–151 行）：若 trun_flags 包含任意 per-sample 标志（如 `AP4_TRUN_FLAG_SAMPLE_SIZE_PRESENT=0x0200`），则 `stream.ReadUI32(m_Entries[0].sample_size)` 向 `m_Items[0]` 写入——该地址超出 0 字节堆分配，造成堆越界写。后续所有 `m_Entries[i]`（i=1,2,...）均为 OOB 写，写入内容来自 MP4 文件后续字节（攻击者可控）。
- **触发条件**: 构造 MP4 文件：moof→traf→trun，trun atom box size 可以很小（例如 28 字节）但 `sample_count` 字段 = 0x10000000，且 trun flags 包含至少一个 per-sample 标志（如 `0x0200` SAMPLE_SIZE_PRESENT）。trun atom 内无需提供完整的 per-sample 数据；stream.ReadUI32 失败返回 0 仍会触发越界写（写入零值）。在 32-bit 编译的 mp42aac 上处理即可触发。
- **安全影响**: 堆越界写，写入数量可达 `0x10000000 * 字段数量` 次，写入内容部分由 MP4 文件后续字节决定（攻击者可控），可覆盖相邻堆块数据或 metadata，具备 RCE 潜力。在 64-bit 系统上，`::operator new(0x10000000*16)` 尝试分配 4GB，抛出 `std::bad_alloc`（未捕获），进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
