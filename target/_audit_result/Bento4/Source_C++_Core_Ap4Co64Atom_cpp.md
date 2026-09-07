Now I have all the context needed. Let me analyze the code carefully.

**Key findings from `Ap4Co64Atom.cpp` lines 71–85:**

```cpp
AP4_Co64Atom::AP4_Co64Atom(AP4_UI32 size, AP4_UI08 version, AP4_UI32 flags, AP4_ByteStream& stream) :
    AP4_Atom(AP4_ATOM_TYPE_CO64, size, version, flags)
{
    stream.ReadUI32(m_EntryCount);
    if (m_EntryCount > (size-AP4_FULL_ATOM_HEADER_SIZE-4)/8) {   // line 78
        m_EntryCount = (size-AP4_FULL_ATOM_HEADER_SIZE-4)/8;      // line 79
    }
    m_Entries = new AP4_UI64[m_EntryCount];                        // line 81
    for (AP4_Ordinal i=0; i<m_EntryCount; i++) {
        stream.ReadUI64(m_Entries[i]);
    }
}
```

`AP4_FULL_ATOM_HEADER_SIZE = 12` (constant from `Ap4Atom.h:61`). The guard expression `(size - AP4_FULL_ATOM_HEADER_SIZE - 4)` is computed in **unsigned 32-bit arithmetic** (`size` is `AP4_UI32`, constant is `AP4_UI32`).

- Gate in `Create()` only requires `size >= 12` (`AP4_FULL_ATOM_HEADER_SIZE`).
- For `size = 12` to `size = 15` (all pass the gate): `size - 12 - 4 = size - 16` **wraps around** to `0xFFFFFFFC` … `0xFFFFFFFF`.
- Division by 8 yields `0x1FFFFFFF` (536,870,911) instead of the intended 0 or negative (clamped-to-0) bound.
- The guard then becomes `if (m_EntryCount > 536870911)` instead of `if (m_EntryCount > 0)`.
- An attacker supplies `m_EntryCount = 0x1FFFFFFF` (≤ threshold, guard does NOT fire) → `new AP4_UI64[536870911]` → attempts ~4 GB allocation → `std::bad_alloc` → process crash (DoS), or for smaller `m_EntryCount` values the loop reads far beyond the declared atom boundary.

## VULN: Integer Underflow in co64 Atom Size Guard Enables OOM Crash / OOB Stream Read
- **漏洞类别**: memory-safety
- **函数**: AP4_Co64Atom::AP4_Co64Atom(AP4_UI32, AP4_UI08, AP4_UI32, AP4_ByteStream&)
- **行号**: 78-81
- **CWE**: CWE-191 (Integer Underflow leading to CWE-789 Memory Allocation with Excessive Size Value)
- **CVSS v3.1**: 6.5 (AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_DefaultAtomFactory::CreateAtomFromStream() → AP4_Co64Atom::Create(size=12, stream) → AP4_Co64Atom::AP4_Co64Atom(size=12, ..., stream) → 行78 unsigned underflow → new AP4_UI64[536870911]
- **描述**: `size` 参数类型为 `AP4_UI32`，`Create()` 仅检查 `size >= AP4_FULL_ATOM_HEADER_SIZE`（即 12），但保护表达式 `(size - AP4_FULL_ATOM_HEADER_SIZE - 4) / 8` 需要 `size >= 16` 才能产生非负结果。当 `size` 为 12–15 时，`size - 12 - 4` 作为无符号减法下溢至 `0xFFFFFFFC`–`0xFFFFFFFF`，除以 8 得到 `0x1FFFFFFF`（536,870,911）。实际边界应为 0，但保护条件变为 `m_EntryCount > 0x1FFFFFFF`，导致攻击者可将文件中的 `m_EntryCount` 字段设置为任意值（最大 0x1FFFFFFF），绕过保护直接触发 `new AP4_UI64[m_EntryCount]`，尝试分配最多 4 GB 内存；或设置小计数使循环越界读取 atom 边界之外的流数据。
- **触发条件**: 构造一个 co64 box，其 box size 字段设为 12（或 13–15），`entry_count` 字段设为 0x1FFFFFFF（≤下溢后的阈值，保护不触发），即可使 `new AP4_UI64[536870911]` 在解析时被执行。
- **安全影响**: 最坏情况为进程因 `std::bad_alloc` 异常终止（DoS / crash）；若系统提交内存（overcommit），也可能导致大量栈外读取，暴露相邻内存数据。

<!-- AUDIT_PROMPT_VERSION: 1 -->
