I have all the context I need. Here is my complete analysis:

**Group 1 — `AP4_TrunAtom` constructor (Ap4TrunAtom.cpp:98-151)**

- Line 105: `stream.ReadUI32(sample_count)` — `sample_count` is fully attacker-controlled.
- Line 127: `m_Entries.SetItemCount(sample_count)` — no validation against `size`, return value **ignored**.
- `SetItemCount` → `EnsureCapacity(count)` → Ap4Array.h:172: `::operator new(count * sizeof(T))`.
- `AP4_Cardinal` = `unsigned int` (32-bit), `sizeof(Entry)` = 16. On 32-bit builds: `count * sizeof(T)` is a 32-bit × 32-bit multiplication. With `count = 0x10000000`, result = `0x100000000` → truncates to **0**. `::operator new(0)` returns a valid minimal allocation; `m_AllocatedCount` is set to `0x10000000`, but the backing buffer is nearly empty. The placement-`new` loop in `SetItemCount` (Ap4Array.h:214-216) then writes up to `0x10000000` × 16 bytes into that tiny buffer → **heap buffer overflow**.
- Compare: `Ap4StcoAtom.cpp:78-79` has `if (m_EntryCount > (size-AP4_FULL_ATOM_HEADER_SIZE-4)/4) { m_EntryCount = ...; }` — the trun atom has no equivalent guard.
- Ignored return of `SetItemCount` (line 127): in `-fno-exceptions` / nothrow builds, if allocation fails, `m_Entries.m_Items` stays NULL; loop at line 128 then dereferences `m_Entries[0]` → **NULL pointer dereference**.

**Group 2 — `EnsureCapacity` (Ap4Array.h:172)**

- `count * sizeof(T)`: both operands 32-bit on 32-bit targets → wraps to 0 or a small number → undersized allocation.

---

## VULN: Integer Overflow in EnsureCapacity → Heap Buffer Overflow via Crafted trun sample_count
- **漏洞类别**: memory-safety
- **函数**: AP4_TrunAtom::AP4_TrunAtom(AP4_UI32, AP4_UI08, AP4_UI32, AP4_ByteStream&) / AP4_Array<T>::EnsureCapacity()
- **行号**: Ap4TrunAtom.cpp:127 → Ap4Array.h:172-184
- **CWE**: CWE-190 (Integer Overflow or Wraparound)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_File::Parse() → AP4_DefaultAtomFactory::CreateAtomFromStream() → Ap4AtomFactory.cpp:402-404 AP4_TrunAtom::Create(size_32, stream) → AP4_TrunAtom(size, version, flags, stream) [Ap4TrunAtom.cpp:98] → stream.ReadUI32(sample_count) [line 105] → m_Entries.SetItemCount(sample_count) [line 127] → EnsureCapacity(count) [Ap4Array.h:166] → ::operator new(count * sizeof(T)) [Ap4Array.h:172]
- **描述**: 在 32 位编译目标上，`EnsureCapacity` 第 172 行将 `count`（`unsigned int`，来自文件字段 `sample_count`）与 `sizeof(Entry)`（16，同为 32 位 `size_t`）相乘时发生无符号整数回绕。例如 `sample_count = 0x10000000`：`0x10000000 × 16 = 0x100000000`，截断为 `0`；`::operator new(0)` 返回一个有效但几乎为零大小的堆块；`m_AllocatedCount` 却被错误地记录为 `0x10000000`；随后 `SetItemCount` 中的 placement-new 循环（Ap4Array.h:214-216）从 `m_Items[0]` 写到 `m_Items[0x10000000-1]`，每项 16 字节，远超实际分配范围，形成堆缓冲区溢出。`Create()` 对 `size` 的唯一检查（Ap4TrunAtom.cpp:48）仅排除 `size < 12` 的情形，不约束 `sample_count`，而其他原子（如 `Ap4StcoAtom.cpp:78-79`）均有形如 `if (count > (size - overhead) / field_size)` 的保护，`trun` 缺失此类校验。
- **触发条件**: 构造一个 fragmented MP4 文件，在 `moof/traf/trun` box 中将 box `size` 设为最小合法值（如 16），同时将 `sample_count` 字段设为 `0x10000000`（32 位目标）或任意超大值。无需有效载荷结构；mp42aac 在解析 moov 后也会解析 moof，trun 会被 `AP4_DefaultAtomFactory::CreateAtomFromStream` 自动触发。
- **安全影响**: 在 32 位编译版本上可实现远程堆缓冲区溢出，覆盖任意堆元数据或相邻对象内容，最坏情况下可被利用为远程代码执行（RCE）；在 64 位编译版本上由于整数不溢出，将触发超大堆分配请求（约 256 MB～64 GB），导致 `std::bad_alloc` 抛出或 OOM Killer，造成拒绝服务（DoS）。

## VULN: Ignored SetItemCount Return Value → NULL Pointer Dereference After OOM
- **漏洞类别**: memory-safety
- **函数**: AP4_TrunAtom::AP4_TrunAtom(AP4_UI32, AP4_UI08, AP4_UI32, AP4_ByteStream&)
- **行号**: Ap4TrunAtom.cpp:127-143
- **CWE**: CWE-476 (NULL Pointer Dereference)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_File::Parse() → AP4_DefaultAtomFactory::CreateAtomFromStream() → AP4_TrunAtom::Create(size_32, stream) → AP4_TrunAtom(size, version, flags, stream) [Ap4TrunAtom.cpp:98] → m_Entries.SetItemCount(sample_count) [line 127，返回值被丢弃] → 分配失败时 m_Entries.m_Items 保持 NULL → m_Entries[i].sample_duration 解引用 [line 130]
- **描述**: 第 127 行 `m_Entries.SetItemCount(sample_count)` 的返回值被完全忽略。在以 `-fno-exceptions` 编译（或使用 nothrow `operator new`）的构建中，若因 `sample_count` 超大导致 `EnsureCapacity` 内部分配失败，`SetItemCount` 将返回 `AP4_ERROR_OUT_OF_MEMORY`，但调用方不检查此返回值，`m_Entries.m_Items` 保持初始 NULL。随后第 128-151 行的循环对 `m_Entries[i]`（即 `NULL[i]`）进行读写，在 `i=0` 时即触发空指针解引用，造成程序崩溃。
- **触发条件**: 在 `-fno-exceptions` 或 nothrow 构建环境中，构造一个 trun box 将 `sample_count` 设为系统可用内存无法满足的超大值（如 `0xFFFFFF` 在内存受限环境下），使分配必然失败。
- **安全影响**: 程序确定性崩溃，造成拒绝服务（DoS）；在某些平台上空指针解引用可被进一步利用。

<!-- AUDIT_PROMPT_VERSION: 1 -->
