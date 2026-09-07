I now have all the information needed for the audit. Let me compile the complete findings.

**Analysis summary across all read files:**

**Group 1 — Ap4TrunAtom.cpp:104-151**: `AP4_TrunAtom` stream constructor reads `sample_count` from file (up to 2^32-1), calls `m_Entries.SetItemCount(sample_count)` with the return value **ignored**. No check against the atom's declared byte size. On standard C++ (throwing `new`): `std::bad_alloc` propagates → unhandled exception → crash (DoS). On nothrow-new: `EnsureCapacity` returns `AP4_ERROR_OUT_OF_MEMORY` silently, `m_Items` stays NULL, `m_ItemCount` stays 0; the loop at line 128 then accesses `m_Entries[0]` = `m_Items[0]` = NULL dereference → crash (DoS/CWE-476).

**Group 2 — Ap4FragmentSampleTable.cpp:57-65**: First loop accumulates `unsigned int sample_count` over multiple trun atoms; overflows to small value → `m_Samples.EnsureCapacity(small)` under-reserves. (By itself this is not the critical path since AddTrun's `SetItemCount` re-grows.)

**Group 3 — Ap4FragmentSampleTable.cpp:119-120**: `AddTrun` does `start + trun->GetEntries().ItemCount()` as a **32-bit unsigned add** with no overflow check; if this wraps to W < start, `SetItemCount(W)` **shrinks** the array (calls `~AP4_Sample()` on indices W..start-1, setting `m_ItemCount = W`). The `SetItemCount` return value is ignored. The subsequent loop at lines 173-226 then accesses `m_Samples[start+i]` (i=0..ItemCount-1) — these are indices beyond `m_ItemCount` and potentially beyond `m_AllocatedCount`, and the AP4_Sample objects there have already had their destructors run. Concretely: `sample.SetDataStream(*sample_stream)` calls `AP4_RELEASE(m_DataStream)` on the destructed object's dangling `m_DataStream` pointer → **use-after-free on ByteStream** + heap OOB write. Practically requires ~192 GB for AP4_Sample objects to trigger, but no upper-bound protection exists.

**Group 4 — Ap4DataBuffer.cpp:192**: `AppendData` overflows `existing_size + data_size` (both AP4_UI32) → `SetDataSize(wrapped)` under-allocates → `AP4_CopyMemory` writes `data_size` bytes past buffer end → heap overflow. NOT on the mp42aac audio extraction path.

**Group 5 — Ap4LinearReader.cpp:105**: `m_BufferFullness -= buffer->m_Data.GetDataSize()` without underflow guard; wraps → blocks all further advancement (DoS). Minor; not directly file-controllable.

## VULN: AP4_TrunAtom sample_count unchecked against atom size — uncontrolled allocation / NULL deref DoS
- **漏洞类别**: memory-safety
- **函数**: AP4_TrunAtom::AP4_TrunAtom() (stream constructor)
- **行号**: 104-151 (Ap4TrunAtom.cpp)
- **CWE**: CWE-190 (Integer Overflow or Wraparound) / CWE-476 (NULL Pointer Dereference)
- **CVSS v3.1**: 6.5 (AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_LinearReader::ReadNextSample() → Advance() → AdvanceFragment() → ProcessMoof() → AP4_MovieFragment::CreateSampleTable() → new AP4_FragmentSampleTable() → AP4_TrunAtom already parsed via atom_factory.CreateAtomFromStream() → AP4_TrunAtom::Create(size_32, stream) → AP4_TrunAtom::AP4_TrunAtom(size, version, flags, stream)
- **描述**: 在 `AP4_TrunAtom` 的流解析构造函数中，`sample_count` 直接从 `trun` box 数据中读取（`stream.ReadUI32(sample_count)`），取值范围 0..2^32-1，随后不加任何边界校验直接传入 `m_Entries.SetItemCount(sample_count)`。该调用的返回值被**完全忽略**。当 `sample_count` 足够大（如 0x10000000 = 268M，对应 `16B*268M = 4GB` 分配）时：（a）若编译器采用标准抛出式 `new`，`EnsureCapacity` 内 `::operator new` 抛出 `std::bad_alloc`，沿调用栈一路传播，因无任何 try-catch 而调用 `std::terminate()` → 进程崩溃；（b）若使用 nothrow 语义的自定义分配器，`EnsureCapacity` 返回 `AP4_ERROR_OUT_OF_MEMORY`（被忽略），`m_Entries.m_Items` 保持 NULL 而 `m_ItemCount` 保持 0，之后 line 128 处的循环在 `i=0` 时访问 `m_Entries[0]` = `m_Items[0]` = 空指针解引用 → SIGSEGV。此外，atom 声明的 `size` 字段存入基类但完全未用于限制 `sample_count` 或后续流读取次数。
- **触发条件**: 构造一个合法格式的分片 MP4 文件，在 `moof/traf` 下放置一个字节体极小（如 16 字节）但 `sample_count` 字段声明为极大值（如 `0x10000000`）的 `trun` box。mp42aac 处理该文件时，atom factory 解析 `trun` box 并调用上述构造函数。
- **安全影响**: 可靠的进程崩溃（DoS）；在 nothrow-new 配置下为 NULL 指针解引用内存安全违规。

## VULN: AP4_FragmentSampleTable::AddTrun 32-bit integer overflow → heap OOB write / use-after-free
- **漏洞类别**: memory-safety
- **函数**: AP4_FragmentSampleTable::AddTrun()
- **行号**: 119-226 (Ap4FragmentSampleTable.cpp)
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow) / CWE-416 (Use After Free)
- **CVSS v3.1**: 7.8 (AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_LinearReader::ReadNextSample() → Advance() → AdvanceFragment() → ProcessMoof() → AP4_MovieFragment::CreateSampleTable() → new AP4_FragmentSampleTable(traf, ...) → AP4_FragmentSampleTable 构造函数循环调用 AddTrun(trun, ...)
- **描述**: 在 `AddTrun` 第 119-120 行：`unsigned int start = m_Samples.ItemCount(); m_Samples.SetItemCount(start + trun->GetEntries().ItemCount());`。`start` 和 `trun->GetEntries().ItemCount()` 均为 `AP4_Cardinal`（32 位无符号整数）。当二者之和超过 2^32 时发生回绕，得到一个远小于 `start` 的值 W。`SetItemCount(W)` 触发数组缩小路径：析构下标 W..start-1 的所有 `AP4_Sample` 对象（其中 `~AP4_Sample()` 会 `AP4_RELEASE(m_DataStream)`，释放流引用），并将 `m_ItemCount = W`；但 `m_AllocatedCount` 及 `m_Items` 指针**不变**（仍指向原大块堆内存）。`SetItemCount` 的返回值被**完全忽略**。之后第 173-226 行循环执行 `AP4_Sample& sample = m_Samples[start+i]`（其中 `i` 从 0 到 `trun->GetEntries().ItemCount()-1`），直接访问已析构的 `AP4_Sample` 内存区域；`sample.SetDataStream(*sample_stream)` 再次调用 `AP4_RELEASE(m_DataStream)`（dangling 指针）→ **对 ByteStream 对象的 use-after-free**，以及对超出 `m_AllocatedCount` 的位置写入 AP4_Sample 字段 → **堆越界写**。整个过程中不存在任何上界校验来阻止 `start` 累积至接近 2^32。
- **触发条件**: 在一个 `traf` box 中嵌入足够多的 `trun` box，使各 `trun` 的 `sample_count` 之和在 32 位下回绕。每个 `trun` 可以声明较小的 `sample_count`（如 1M），通过大量 `trun`（如 4096 个，合计 ≈ 4G samples）触发溢出。实际利用需要系统有足够内存运行前 4095 个 `trun` 的 AP4_Sample 分配（~192 GB，极端场景）；在资源受限的虚拟化/容器环境中，即使在溢出点之前即可触发 OOM 崩溃形成 DoS。
- **安全影响**: 最坏情况下堆内存破坏（写入 + use-after-free），结合精心布局的堆状态可进一步利用为远程代码执行（RCE）；实际场景中由于内存限制更常见的是可靠的进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
