Now I have full context. Let me analyze all the findings systematically.

**Group 1 — `Ap4ElstAtom.cpp` constructor (lines 65-95)**

Key path:
```cpp
AP4_UI32 entry_count;
stream.ReadUI32(entry_count);             // unchecked, from file
m_Entries.EnsureCapacity(entry_count);   // return value IGNORED
for (AP4_UI32 i=0; i<entry_count; i++) {
    ...
    m_Entries.Append(AP4_ElstEntry(...));
}
```

No validation of `entry_count` against box `size`. No upper-bound check of any kind.

**Group 2 — `Ap4Array.h` `EnsureCapacity` (line 172)**

```cpp
T* new_items = (T*) ::operator new (count*sizeof(T));
...
m_Items = new_items;
m_AllocatedCount = count;   // stores the REQUESTED count, not actual bytes/elem-capacity
```

Types: `count` = `AP4_Cardinal` = `unsigned int` (32-bit even on 64-bit host). `sizeof(T)` = `size_t`.

On **64-bit** systems: `unsigned int * size_t` → `unsigned int` is promoted to `size_t` before multiply → 64-bit multiplication, no overflow. Large `entry_count` → `std::bad_alloc` → DoS only.

On **32-bit** systems: `size_t` is also 32-bit → `unsigned int * unsigned int` = 32-bit multiplication → **integer overflow possible**.

Example for `sizeof(AP4_ElstEntry)` = 20 on 32-bit:
- `count = 0x0CCCCCCD` → `0x0CCCCCCD × 20 = 0x100000009A` → truncated to 32-bit: `0x9A = 154 bytes`
- `new` allocates 154 bytes (≈7 entries), but `m_AllocatedCount = 0x0CCCCCCD`
- Append then checks `m_AllocatedCount < m_ItemCount+1` → `0x0CCCCCCD < 1` → **false** → no realloc
- Loop writes `m_Items[0]`, `m_Items[1]`, … `m_Items[7]` (OOB at index 8+) → **heap buffer overflow**

Additionally, the `EnsureCapacity` return value is ignored on line 73 of Ap4ElstAtom.cpp, so any silent failure path also cascades into the loop unchecked.

There is **no explicit upper-bound check** (`entry_count <= (size - header) / entry_size`) anywhere in the elst parser — unlike other atoms in the same codebase (e.g., `Ap4StssAtom.cpp:78`, `Ap4StscAtom.cpp:78`, `Ap4SaioAtom.cpp:110`) which all perform such guards.

## VULN: Integer Overflow in AP4_Array EnsureCapacity Causes Heap Buffer Overflow in elst Parser
- **漏洞类别**: memory-safety
- **函数**: AP4_ElstAtom::AP4_ElstAtom() / AP4_Array<T>::EnsureCapacity()
- **行号**: Ap4ElstAtom.cpp:72-94 / Ap4Array.h:172-184
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 7.5 (AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_File → AP4_DefaultAtomFactory → AP4_ElstAtom::Create() → new AP4_ElstAtom(size, version, flags, stream) → AP4_Array<AP4_ElstEntry>::EnsureCapacity(entry_count) → ::operator new(count * sizeof(T)) [32-bit overflow] → AP4_Array<AP4_ElstEntry>::Append() OOB write
- **描述**: `entry_count` 从 elst box 数据流中读取（AP4_UI32），无任何上界校验。随后调用 `m_Entries.EnsureCapacity(entry_count)`，在 `EnsureCapacity` 内部执行 `count * sizeof(T)`。在 32-bit 编译目标上，`count`（AP4_Cardinal = unsigned int，32 位）乘以 `sizeof(AP4_ElstEntry)`（亦为 32 位 size_t）产生 32-bit 整数溢出，导致 `::operator new` 仅分配极少字节（如 count=0x0CCCCCCD，sizeof=20 时溢出为 154 字节），但 `m_AllocatedCount` 被赋值为原始大值 `count`。此后构造函数循环 `entry_count` 次调用 `Append`，`Append` 检查 `m_AllocatedCount < m_ItemCount+1` 始终为假而不触发重新分配，直接通过 placement new 向越界偏移写入 `AP4_ElstEntry` 对象，造成堆缓冲区溢出。此外，`EnsureCapacity` 返回值在 Ap4ElstAtom.cpp:73 被完全忽略，使任何静默失败路径均无法中断后续循环。同一代码库中其他 atom（stss、stsc、saio）均在读取 entry_count 后显式校验 `(size - header) / entry_size < entry_count`，独 elst 缺此保护。
- **触发条件**: 构造一个合法 MP4 文件，其 moov/trak/edts/elst box 中将 size 字段设置为最小合法值（如 16 字节，仅含 full atom header 和 entry_count 字段），同时将 entry_count 设为能使 `entry_count * sizeof(AP4_ElstEntry)` 在 32-bit 运算中溢出的特定大值（如 0x0CCCCCCD）；在 32-bit 部署的 mp42aac 上解析该文件即可触发。
- **安全影响**: 堆内存越界写入任意 AP4_ElstEntry 内容（包含攻击者可控的 SegmentDuration/MediaTime/MediaRate 字段），可覆盖堆管理元数据或相邻对象，最坏情况下可实现远程代码执行（RCE）；在 64-bit 目标上退化为 `std::bad_alloc` 导致进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
