**Analysis complete.** All 646 lines of `Ap4LinearReader.cpp` have been read. Key contextual data gathered:

- `AP4_Array::operator[]` — **no bounds check** (line 67 of `Ap4Array.h`): `T& operator[](unsigned long idx) { return m_Items[idx]; }`
- `AP4_Size` = `AP4_UI32` (32-bit unsigned), `AP4_Position` = `AP4_UI64`
- `AP4_TfraAtom` populates `m_Entries` from file: `stream.ReadUI32(entry_count)` → `m_Entries.SetItemCount(entry_count)` — fully attacker-controlled count per track
- `SeekTo()` is a public API; no current Bento4 app calls it, but `AP4_LinearReader` is used by `mp4diff`, `mp4fragment`, `mp4iframeindex`, `mp42ts`, `mp42hls`

**Confirmed vulnerability:** In `SeekTo()` lines 207–249, `best_entry` is set as an index into the first tracker's `entries` array (`AP4_Array<AP4_TfraAtom::Entry>&`). When the loop advances to tracker `t+1`, `entries` is re-bound to that tracker's (potentially shorter) array, but `best_entry` (from tracker `t`'s larger array) is used unchecked to index the new `entries` at lines 237, 245, 247 — a heap OOB read.

## VULN: SeekTo() cross-tracker OOB read via stale best_entry index
- **漏洞类别**: memory-safety
- **函数**: AP4_LinearReader::SeekTo()
- **行号**: 237-247
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 5.4 (AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:L)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: 攻击者提供精心构造的 fragmented MP4 文件（含 mfra box，含 ≥2 个 tfra atom，各 tfra 的 entry_count 不等） → 任何调用 AP4_LinearReader::SeekTo() 的应用程序（如扩展 mp42ts/mp42hls 场景或第三方 Bento4 库消费者） → AP4_LinearReader::SeekTo()（Ap4LinearReader.cpp:156） → 内层 for 循环第二轮迭代 entries[best_entry]（行 237/245/247）
- **描述**: `SeekTo()` 在外层 `for (unsigned t=0; t<m_Trackers.ItemCount(); t++)` 中，每次迭代将局部引用 `entries` 绑定到当前 tracker 对应 tfra 的条目数组（行 226：`AP4_Array<AP4_TfraAtom::Entry>& entries = tfra->GetEntries()`）。`best_entry` 在第一个 tracker（t=0）处被赋值为该 tracker 找到的条目下标（最大可为 N-1）。当 t=1 时，`entries` 切换为第二个 tracker 的数组（可能只有 M < N 个元素），但行 237（`entries[best_entry].m_MoofOffset`）、行 245（`entries[best_entry].m_Time`）、行 247（`entries[best_entry].m_MoofOffset`）仍然以 `best_entry`（来自 t=0 的大索引）直接访问 t=1 的小数组。`AP4_Array::operator[]` 无任何边界检查（`return m_Items[idx]`），因此发生堆越界读。读取的堆外数据被写入调用者传入的 `*actual_time_ms` 并设置到 `m_NextFragmentPosition`，后者将驱动后续 Seek/解析操作。
- **触发条件**: 1) 构造 fragmented MP4，在文件末尾放置 `mfra` box；2) `mfra` 内含 ≥2 个 `tfra` atom，其中 track 0 的 `tfra` 含 N 个条目（N 较大），track 1 的 `tfra` 含 M 个条目（M < N，即 M ≤ best_entry-1）；3) 选择 seek time 使得 track 0 的 `entry = N-1`（即 `best_entry = N-1`），track 1 也有可用 entry（`entry >= 0`），从而触发 `entries[N-1]` 在仅有 M 个元素的数组上的越界访问。
- **安全影响**: 堆越界读泄露 tfra 条目数组之后的堆内存内容（可能包含堆元数据、指针、其他对象数据），造成信息泄露；读取到的 `m_MoofOffset` 被写入 `m_NextFragmentPosition`，导致后续 `m_FragmentStream->Seek()` 跳转到攻击者通过堆布局间接控制的位置，可进一步触发对任意流偏移处数据的 MP4 box 解析，构成更高危利用链的跳板；若越界读命中不可访问内存页则进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
