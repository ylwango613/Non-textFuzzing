I now have enough context. Let me do the final review of the complete picture before writing the report.

**Key findings from analysis:**

**Group 1 — `AP4_TrunAtom` constructor (Ap4TrunAtom.cpp:98–151):**
- `sample_count` read from file (line 105), passed directly to `m_Entries.SetItemCount(sample_count)` (line 127)
- `SetItemCount` calls `EnsureCapacity(count)` which does `::operator new(count * sizeof(T))`
- On 32-bit: `count * sizeof(AP4_TrunAtom::Entry)` = `count * 16` overflows at count ≥ 0x10000000 → `::operator new(0)` → allocates ~0 bytes → placement-new loop and read loop in constructor write 268M+ entries → massive heap OOB writes
- No validation of `sample_count` against declared atom `size` (unlike `AP4_TfhdAtom::Create` which does `if (size < ComputeSize(flags)) return NULL`)
- On 64-bit: no arithmetic overflow but `std::bad_alloc` → DoS

**Group 2 — `AP4_FragmentSampleTable::AddTrun` (Ap4FragmentSampleTable.cpp:119–120):**
- `start + trun->GetEntries().ItemCount()` both 32-bit unsigned → can overflow
- If sum overflows to a small value, `SetItemCount(small)` shrinks the array (destructs items, does NOT free buffer, keeps `m_AllocatedCount` at old large value) → subsequent loop `m_Samples[start+i]` accesses one-past-end and beyond → heap OOB writes
- In practice subsumed by Group 1 on 32-bit (TrunAtom Entry allocation OOMs or overflows first); on 64-bit requires > 32GB allocation for first trun → not feasible

**Record_fields_count bug (Ap4TrunAtom.cpp:126–150):** Cumulative decrement across iterations causes drift for unknown flags but only a logic/parsing issue; no memory corruption.

**Pre-scan overflow in constructor (Ap4FragmentSampleTable.cpp:57–66):** `sample_count += trun->GetEntries().ItemCount()` sums can overflow but `AddTrun`'s `SetItemCount` re-allocates as needed → harmless.

The only clearly exploitable memory-safety finding is the integer overflow in `AP4_TrunAtom` constructor leading to heap buffer overflow on 32-bit builds (with DoS on 64-bit). I'll also report the `AddTrun` overflow as a separate finding since it meets the stated reporting criteria (file-controlled count, can overflow, no upper-bound check).

## VULN: Integer Overflow in AP4_TrunAtom sample_count → Heap Buffer Overflow
- **漏洞类别**: memory-safety
- **函数**: AP4_TrunAtom::AP4_TrunAtom(AP4_UI32 size, AP4_UI08 version, AP4_UI32 flags, AP4_ByteStream& stream)
- **行号**: 98-151 (Ap4TrunAtom.cpp), 核心溢出于 127 行 (SetItemCount) 和 166-186 行 (EnsureCapacity 内部 `count*sizeof(T)`)
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: `mp42aac input.mp4` → `AP4_LinearReader::AdvanceFragment()` → `AP4_DefaultAtomFactory::CreateAtomFromStream()` → `AP4_TrunAtom::Create(size, stream)` → `new AP4_TrunAtom(size, version, flags, stream)` → `stream.ReadUI32(sample_count)` [从文件读取] → `m_Entries.SetItemCount(sample_count)` → `AP4_Array<Entry>::EnsureCapacity(sample_count)` → `::operator new(sample_count * sizeof(Entry))` [整数溢出] → 构造/读取循环执行 `sample_count` 次越界写入
- **描述**: `AP4_TrunAtom` 的解析构造函数在第 105 行从 MP4 流读取 `sample_count`（`AP4_UI32`，4 字节，取值完全受攻击者控制），随后在第 127 行直接调用 `m_Entries.SetItemCount(sample_count)`，进而触发 `EnsureCapacity(sample_count)` 中的 `::operator new(count * sizeof(AP4_TrunAtom::Entry))`（`Ap4Array.h:172`）。`count` 为 32 位无符号整数，`sizeof(Entry) = 16`；在 **32 位构建**中两者相乘为 32 位算术，当 `sample_count ≥ 0x10000000`（268,435,456）时乘积 ≥ 0x100000000，发生整数回绕，例如 `0x10000000 × 16 = 0` → `::operator new(0)` 仅分配约 0 字节，但 `m_AllocatedCount` 和 `m_ItemCount` 均被错误设置为 `0x10000000`。随后 `SetItemCount` 的 placement-new 循环（`Ap4Array.h:214-216`）和 `AP4_TrunAtom` 构造函数中的读取循环（第 128-151 行）均对该微型缓冲区执行多达 2.68 亿次越界写操作，导致严重堆内存破坏。`AP4_TrunAtom::Create` 仅检查 `size < AP4_FULL_ATOM_HEADER_SIZE`，缺乏 `sample_count` 与原子声明大小的对齐校验（对比 `AP4_TfhdAtom::Create` 中存在 `size < ComputeSize(flags)` 检查），漏洞路径无任何上界守卫。在 **64 位构建**中乘法无溢出，但 `::operator new(~64 GB)` 抛出 `std::bad_alloc`，进程崩溃，构成拒绝服务。
- **触发条件**: 构造一个合法的 MP4 fragmented 文件：在 `moof/traf` 容器中内嵌一个 `trun` 原子，其声明体积极小（如仅 12 字节），但将 `sample_count` 字段设置为 `0x10000000` 或更大值（对于 32 位构建）或任何大值（对于 64 位构建 DoS）；`trun` 原子内无需包含实际的 per-sample 数据字节。
- **安全影响**: 32 位构建下：可控堆内存越界写（写入内容可包含从流读取的任意字节），攻击者可通过精心布局堆布局实现任意代码执行（RCE）。64 位构建下：进程因 `std::bad_alloc` 未捕获而崩溃，拒绝服务（DoS）。

## VULN: Unsigned Integer Overflow in AddTrun start+count → m_Samples Heap OOB Write
- **漏洞类别**: memory-safety
- **函数**: AP4_FragmentSampleTable::AddTrun()
- **行号**: 119-120 (Ap4FragmentSampleTable.cpp)
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-787 (Out-of-bounds Write)
- **CVSS v3.1**: 7.8 (AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: `mp42aac input.mp4` → `AP4_LinearReader::ProcessMoof()` → `AP4_MovieFragment::CreateSampleTable()` → `new AP4_FragmentSampleTable(traf, ...)` → 构造函数遍历所有 `trun` 原子，每个调用 `AddTrun()` → `start + trun->GetEntries().ItemCount()` 32 位无符号溢出 → `m_Samples.SetItemCount(wrapped_small)` → `m_Samples` 逻辑容量缩减但底层缓冲区未释放 → 后续循环 `m_Samples[start+i]`（`Ap4FragmentSampleTable.cpp:175`）越界写
- **描述**: 在 `AddTrun` 函数中，第 119 行取 `start = m_Samples.ItemCount()`（当前已累计样本数，来自之前 trun 处理结果），第 120 行计算 `start + trun->GetEntries().ItemCount()`（两者均为 `AP4_Cardinal` = `unsigned int`，32 位），作为参数传入 `m_Samples.SetItemCount()`。若两者之和超过 `0xFFFFFFFF` 则发生 32 位无符号回绕，得到一个远小于 `start` 的值（如为 0 或极小正数）。`SetItemCount(wrapped_small)` 进入缩减分支（`Ap4Array.h:200-206`）：析构多余元素并将 `m_ItemCount` 设为 `wrapped_small`，但 **不释放底层缓冲区**，`m_AllocatedCount` 保持为 `start`（旧的大容量）。随后第 173-226 行的循环仍以 `trun->GetEntries().ItemCount()`（即第二个 trun 的完整 entry 数）为上限遍历，在第 175 行执行 `m_Samples[start + i]`，其中 `start` 为原有大值；当 `start + i ≥ m_AllocatedCount` 时发生越界写，破坏 `m_Samples` 缓冲区后方的堆内存。`operator[]` 无边界检查（`Ap4Array.h:67`）。
- **触发条件**: MP4 文件中同一 `traf` 容器内包含两个 `trun` 原子：第一个 `trun` 的 `sample_count` 足够大（使 `m_Samples` 扩容到大值 `start`），第二个 `trun` 的 `sample_count` 满足 `start + count2` 恰好发生 32 位无符号回绕（即 `count2 = 2^32 - start + ε`）。在实际 32 位构建中，受地址空间限制，较小的 `start` 值（如数百万级）即可实现可利用的布局。
- **安全影响**: 堆缓冲区越界写，写入内容受 `AP4_Sample` 各字段赋值（大小、偏移、时间戳等，部分来自文件字段）控制，可导致后续堆元数据或其他对象损坏，最坏情况可实现任意代码执行（RCE）或进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
