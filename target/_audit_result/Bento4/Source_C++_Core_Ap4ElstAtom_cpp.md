Now I have all the information needed. Let me trace the complete vulnerability chain:

**Key findings:**

1. `AP4_Cardinal` = `unsigned int` (32-bit), `AP4_Size` = `AP4_UI32` (32-bit).
2. In `AP4_ElstAtom` constructor (line 72-73): `entry_count` is read directly from the stream with no bounds check against the box `size`. `EnsureCapacity(entry_count)` return value is **silently discarded**.
3. In `AP4_Array<T>::EnsureCapacity` (Ap4Array.h line 172): allocation is `::operator new(count * sizeof(T))`. `count` is `AP4_Cardinal` = `unsigned int`. On a 32-bit build (`sizeof(size_t)` = 4), this multiplication is 32-bit × 32-bit — integer overflow is possible.
4. `sizeof(AP4_ElstEntry)` = 24 bytes. When `count = 0x20000000` (536870912): `536870912 × 24 = 12884901888`, which wraps to **0** mod 2³² on a 32-bit build. `::operator new(0)` returns a valid but zero-byte buffer. `m_AllocatedCount` is then set to 0x20000000. Every subsequent `Append` call skips the grow check (`m_AllocatedCount ≥ m_ItemCount+1` is true) and writes directly to `m_Items[i]` — all out-of-bounds heap writes.

## VULN: Integer Overflow in EnsureCapacity Leads to Heap Buffer Overflow via Crafted elst entry_count
- **漏洞类别**: memory-safety
- **函数**: AP4_Array<AP4_ElstEntry>::EnsureCapacity() / AP4_ElstAtom::AP4_ElstAtom()
- **行号**: 72-94 (Ap4ElstAtom.cpp) / 166-187 (Ap4Array.h)
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_File::AP4_File() → AP4_AtomFactory::CreateAtomFromStream() → AP4_ElstAtom::Create() → AP4_ElstAtom::AP4_ElstAtom(size, version, flags, stream) → AP4_Array<AP4_ElstEntry>::EnsureCapacity(entry_count) → AP4_Array<AP4_ElstEntry>::Append() × N
- **描述**: 在 AP4_ElstAtom 构造函数（Ap4ElstAtom.cpp:72–73）中，`entry_count` 直接从 MP4 文件的 elst box 数据流中读取，随即以 `m_Entries.EnsureCapacity(entry_count)` 传入 AP4_Array。在 32-bit 构建中，`AP4_Cardinal`（即 `unsigned int`，32-bit）与 `sizeof(AP4_ElstEntry)`（24 字节）的乘积在 `AP4_Array::EnsureCapacity`（Ap4Array.h:172）执行 `count * sizeof(T)` 时发生整数溢出：当 `entry_count = 0x20000000`（536870912）时，`536870912 × 24 = 12884901888 ≡ 0 (mod 2³²)`，`::operator new(0)` 返回一个零字节缓冲区，但 `m_AllocatedCount` 却被错误地设置为 0x20000000。此后构造函数循环调用 `Append` 达 5.36 亿次，每次调用均因 `m_AllocatedCount ≥ m_ItemCount+1` 绕过扩容检查，直接向 `m_Items[i]`（实际为 0 字节缓冲区之外）写入 24 字节结构体，造成大规模堆溢出写入。EnsureCapacity 的返回值在调用处（Ap4ElstAtom.cpp:73）完全未检查，即使分配失败也无法中止后续循环。
- **触发条件**: 攻击者构造一个 MP4 文件，其中 elst box 的 `size` 字段足够大（或使用 64-bit largesize），`entry_count` 字段设置为 0x20000000（或满足 `entry_count × 24 ≡ 0 mod 2³²` 的其他值，如 0x15555556 等），从而在 32-bit 目标进程中触发 EnsureCapacity 整数溢出。
- **安全影响**: 堆内存大量越界写入，攻击者可精心控制写入内容（每条 entry 的 segment_duration、media_time、media_rate 字段均来自文件），在目标堆对象上实施任意写，最坏情况可达远程代码执行（RCE）；在 64-bit 构建中，`::operator new` 尝试分配约 96 GB 内存，将抛出 `std::bad_alloc` 异常导致进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
