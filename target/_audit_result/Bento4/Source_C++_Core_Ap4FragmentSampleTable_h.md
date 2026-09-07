I have now read all relevant files end-to-end. Here is my complete analysis before writing the final report:

**Group 1 – Ap4Array.h (`EnsureCapacity`, line 172):**
- `count` is `AP4_Cardinal = unsigned int` (32-bit); `sizeof(T)` is `size_t` (32-bit on 32-bit targets).
- Multiplication `count * sizeof(T)` is **32-bit × 32-bit = 32-bit arithmetic on 32-bit targets**, meaning integer overflow is possible.
- With `count = 0x10000000` and `sizeof(AP4_TrunAtom::Entry) = 16`: `0x10000000 × 16 = 0x100000000 mod 2³² = 0` → `::operator new(0)` returns a tiny but valid allocation; `m_AllocatedCount` is then set to the large value `0x10000000`.
- `SetItemCount` (line 214) then placement-constructs `0x10000000` `Entry` objects at `m_Items[0..0x10000000-1]` — all indices ≥ 1 are OOB → **heap buffer overflow**.
- On 64-bit: `sizeof(T)` promotes `count` to 64-bit, so `0x10000000 × 16 = 4 GB` — no wrap. Not exploitable on 64-bit.

**Group 2 – Ap4TrunAtom.cpp (constructor, line 127):**
- `sample_count` is read directly from the file with no upper-bound validation against the atom's declared `size`.
- `m_Entries.SetItemCount(sample_count)` return value is **not checked** (line 127). On 32-bit, the EnsureCapacity overflow above is the exploitable path. On nothrow builds, a NULL `m_Items` would cause NULL dereference — but nothrow is a non-default option, so not reported.

**Group 3 – Ap4FragmentSampleTable.cpp (`AddTrun`, line 120):**
- `m_Samples.SetItemCount(start + trun->GetEntries().ItemCount())` return value **not checked**. With nothrow: subsequent `m_Samples[start+i]` is OOB. Not reported (non-default build condition).
- The 32-bit addition `start + trun->GetEntries().ItemCount()` can wrap, but reaching overflow requires accumulating > 4B entries across prior truns — requiring multi-GB allocations that are infeasible in practice.

**Group 4 – Signed/unsigned arithmetic in `AddTrun` (data_offset):**
- `data_offset += trun->GetDataOffset()` where `GetDataOffset()` returns `AP4_SI32`. Sign-extension is intentional per ISOBMFF spec (negative offsets allowed). No memory corruption.

**Confirmed exploitable vulnerability: integer overflow in `EnsureCapacity` on 32-bit targets, triggered through `AP4_TrunAtom` construction from a crafted MP4 file.**

---

## VULN: Integer Overflow in AP4_Array::EnsureCapacity via Crafted trun atom sample_count → Heap Buffer Overflow
- **漏洞类别**: memory-safety
- **函数**: AP4_Array<T>::EnsureCapacity() (Ap4Array.h:172)，触发入口为 AP4_TrunAtom::AP4_TrunAtom() (Ap4TrunAtom.cpp:127)
- **行号**: Ap4Array.h:172; Ap4TrunAtom.cpp:104-151
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-Based Buffer Overflow)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac input.mp4 → AP4_File 解析 → AP4_AtomFactory::CreateAtomFromStream (Ap4AtomFactory.cpp:404) → AP4_TrunAtom::Create(size_32, stream) → AP4_TrunAtom 构造函数 → stream.ReadUI32(sample_count) 读取攻击者控制的 0x10000000 → m_Entries.SetItemCount(0x10000000) → AP4_Array<Entry>::EnsureCapacity(0x10000000) → ::operator new(count * sizeof(T)) 在32位目标上整数溢出归零 → 分配极小内存但 m_AllocatedCount 被设为 0x10000000 → SetItemCount 在极小缓冲区上连续构造 0x10000000 个 Entry 对象 → 堆越界写入
- **描述**: 在32位编译目标上，`AP4_Array<T>::EnsureCapacity`（Ap4Array.h:172）计算分配大小的表达式为 `count * sizeof(T)`，其中 `count` 为 `AP4_Cardinal = unsigned int`（32位），`sizeof(AP4_TrunAtom::Entry) = 16` 字节，在32位平台上 `sizeof` 返回 `size_t = unsigned int`（32位）。当 `count = 0x10000000` 时，`0x10000000 × 16 = 0x100000000` 在32位无符号运算下溢出归零，`::operator new(0)` 返回合法但极小的分配指针；随后 `m_AllocatedCount` 被赋值为 0x10000000（大值），`SetItemCount` 在仅有零字节（或最小对齐块）的缓冲区上使用 placement new 构造 0x10000000 个对象（Ap4Array.h:214），从 `m_Items[1]` 起全部越界，大量覆盖相邻堆块。攻击者只需提供声明 `size` 仅20字节、`sample_count = 0x10000000`、flags=0（无 record 字段）的 `trun` atom，无需任何实际 sample payload。
- **触发条件**: 构造包含 `moof → traf → trun` 结构的 MP4 文件：trun atom 总大小声明为 20 字节（合法最小值：12字节 full atom header + 4字节 sample_count 字段，flags=0），`sample_count` 字段设为 `0x10000000`（或任意满足 `N × 16 ≡ 0 mod 2^32` 的值，如 `0x80000000` 对应 `N × 16 = 0x10` 使溢出结果更小）。
- **安全影响**: 堆缓冲区大量越界写入，覆盖堆管理结构（如 malloc chunk header）及紧邻对象，攻击者可精心布局堆内存以实现任意代码执行（RCE）；最低影响为进程崩溃（DoS/SIGSEGV）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
