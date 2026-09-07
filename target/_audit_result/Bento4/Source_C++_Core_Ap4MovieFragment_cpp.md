I have gathered all necessary context. Now synthesizing the findings from all code paths:

**Group 1 — `Ap4TrunAtom.cpp` trun constructor (lines 104–151):**
- `sample_count` read directly from file (line 105) with no validation against atom `size`
- `m_Entries.SetItemCount(sample_count)` (line 127) calls `EnsureCapacity(sample_count)` in `Ap4Array.h:172`: `::operator new(count * sizeof(Entry))` where `sizeof(Entry) = 16`
- On 32-bit: `count * sizeof(T)` is `uint32_t * uint32_t` arithmetic — when `count = 0x10000000`, `0x10000000 * 16 = 0x100000000` wraps to **0**, so `::operator new(0)` returns a minimal block; `m_AllocatedCount = 0x10000000` and `m_ItemCount = 0x10000000`; the subsequent loop (lines 128–151) writes `0x10000000` `Entry` structs into the ~16-byte allocation → massive heap overflow
- On 64-bit: multiplication is widened to 64-bit, no wrap; but `sample_count = 0x10000000` still requests 4 GB, causing `std::bad_alloc` (uncaught in the tool) → DoS

**Group 2 — `Ap4FragmentSampleTable.cpp:AddTrun` (lines 119–120):**
- `unsigned int start = m_Samples.ItemCount();`
- `m_Samples.SetItemCount(start + trun->GetEntries().ItemCount());` — both operands are `unsigned int`; unchecked 32-bit wrapping addition
- If multiple trun atoms cause `start + count` to wrap to a value < `start`, `SetItemCount` **shrinks** the array (destructing AP4_Sample objects at indices `[wrapped_val .. start-1]`), but the loop immediately below (line 173) accesses `m_Samples[start + i]` using the pre-wrap `start`, indexing into destructed heap objects → use-after-free / OOB write
- Practically this requires total entries > 2³², which is memory-constrained and hard to trigger in isolation, but the integer overflow itself has no guard

## VULN: Integer Overflow in AP4_Array::EnsureCapacity via Trun sample_count → Heap Buffer Overflow (32-bit) / DoS (64-bit)
- **漏洞类别**: memory-safety
- **函数**: AP4_TrunAtom::AP4_TrunAtom() → AP4_Array<Entry>::EnsureCapacity()
- **行号**: Ap4TrunAtom.cpp:104–151 (integer overflow at call to SetItemCount line 127); Ap4Array.h:172 (overflow site count*sizeof(T))
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac input.mp4 → AP4_File::AP4_File() → AP4_AtomFactory::CreateAtomFromStream() → AP4_TrunAtom::Create(size_32, stream) → AP4_TrunAtom::AP4_TrunAtom(size, version, flags, stream) [Ap4TrunAtom.cpp:104] → stream.ReadUI32(sample_count) [line 105] → m_Entries.SetItemCount(sample_count) [line 127] → AP4_Array<Entry>::EnsureCapacity(count) [Ap4Array.h:166] → ::operator new(count * sizeof(T)) [line 172]
- **描述**: `AP4_TrunAtom` 的流式构造函数直接从文件中读取 32 位 `sample_count` 字段（Ap4TrunAtom.cpp:105），不对其与 atom 声明大小做任何校验，随即调用 `m_Entries.SetItemCount(sample_count)`（行 127）。`SetItemCount` 调用 `EnsureCapacity(count)`（Ap4Array.h:166），在其中计算 `::operator new(count * sizeof(T))`（行 172），其中 `T = AP4_TrunAtom::Entry`，`sizeof(T) = 16`。在 32 位编译目标上，`count` 与 `sizeof(T)` 均为 32 位宽度，当 `count = 0x10000000` 时 `0x10000000 × 16 = 0x100000000`，在 `size_t`（32 位）上回绕为 0；`::operator new(0)` 返回仅几字节的最小分配，但 `m_AllocatedCount` 被错误地设为 `0x10000000`，`m_ItemCount` 同样被设为 `0x10000000`。紧随其后的 `for (unsigned int i=0; i<sample_count; i++)` 循环（行 128–151）对每个条目调用 `stream.ReadUI32(m_Entries[i].sample_duration)` 等字段写入，将 2.68 亿条 16 字节条目写入只有数字节的堆缓冲区，造成大规模堆缓冲区溢出。在 64 位目标上，乘法不溢出，但 `count = 0x10000000` 请求 4 GB 分配，`::operator new` 抛出 `std::bad_alloc`，mp42aac 未捕获该异常，导致进程终止（DoS）。
- **触发条件**: 构造一个 MP4 文件，在 moof/traf 容器内嵌入一个 trun atom，其声明大小可以极小（≥12 字节，即全量 atom 头部最小值），但 `sample_count` 字段（大小域后紧随的 4 字节）设置为 `0x10000000`（32 位 RCE 路径）或任意大值（64 位 DoS 路径）。`AP4_TrunAtom::Create` 仅校验 `size >= AP4_FULL_ATOM_HEADER_SIZE`（12 字节），不验证 `sample_count` 是否与 atom payload 实际字节数匹配。
- **安全影响**: 在 32 位系统上，可控大小的堆缓冲区溢出覆盖相邻堆元数据及其他对象，结合现代堆利用技术可实现任意代码执行（RCE）。在 64 位系统上，触发未捕获的 `std::bad_alloc` 异常导致进程崩溃（DoS）。两种路径均无需特殊权限，仅需诱使用户对恶意 MP4 文件运行 mp42aac。

## VULN: Unchecked Unsigned Integer Overflow in AddTrun sample count accumulation → OOB Write to Destructed AP4_Sample Objects
- **漏洞类别**: memory-safety
- **函数**: AP4_FragmentSampleTable::AddTrun()
- **行号**: Ap4FragmentSampleTable.cpp:119–175
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-787 (Out-of-Bounds Write)
- **CVSS v3.1**: 6.7 (AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac input.mp4 → AP4_MovieFragment::CreateSampleTable() [Ap4MovieFragment.cpp:156] → new AP4_FragmentSampleTable(traf, ...) [Ap4FragmentSampleTable.cpp:45] → AddTrun(trun, ...) [Ap4FragmentSampleTable.cpp:83] → m_Samples.SetItemCount(start + ItemCount()) [Ap4FragmentSampleTable.cpp:120] → AP4_Array<AP4_Sample>::SetItemCount()
- **描述**: 在 `AP4_FragmentSampleTable::AddTrun`（Ap4FragmentSampleTable.cpp:119–120）中，`start`（当前 `m_Samples` 元素数，类型 `unsigned int`）与 `trun->GetEntries().ItemCount()`（类型 `AP4_Cardinal = unsigned int`）相加后直接传入 `m_Samples.SetItemCount()`，对该加法没有溢出检查。若多个 trun atom 使累积总样本数超过 `UINT_MAX`，则 `start + count` 回绕为一个小于 `start` 的值 Z。`SetItemCount(Z)` 判断 `Z < m_ItemCount`，触发数组收缩逻辑，调用 `m_Items[Z..start-1]` 范围内所有 `AP4_Sample` 对象的析构函数（释放各自的 `m_DataStream` 引用等资源），并将 `m_ItemCount` 更新为 Z。紧接着 `AddTrun` 中的循环（行 173）以原 `start` 值为基址访问 `m_Samples[start + i]`（`unsigned int` 加法同样可能再次回绕），对刚刚析构的 `AP4_Sample` 内存执行 `SetSize`、`SetOffset`、`SetDataStream` 等写操作，造成对已析构堆对象的越界写入（CWE-787）和潜在的 use-after-free（CWE-416）。
- **触发条件**: 构造包含多个 trun atom 的 moof 分片，使所有 trun 的 sample_count 之和超过 `0xFFFFFFFF`（4,294,967,295）。在内存充足的 32 位系统上，可通过每个 trun atom 携带较小的 sample_count 并嵌入大量 trun atom 来触发（每个 trun 独立分配成功，累积和溢出）。实际可利用性受限于所需的总内存量。
- **安全影响**: 最坏情况下，对已释放堆内存的受控写入可破坏堆元数据，结合 AP4_Sample 析构引发的虚假引用计数变更，可被利用实现任意代码执行（RCE）或进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
