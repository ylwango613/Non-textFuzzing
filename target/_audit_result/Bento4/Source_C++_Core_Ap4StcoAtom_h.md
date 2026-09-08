Now I have enough context. Let me complete the analysis.

**Analysis of Ap4StcoAtom.cpp, the parsing constructor (lines 71-92):**

The private constructor parses the stco box from stream:
- Line 77: reads `m_EntryCount` from stream (attacker-controlled)  
- Line 78: bounds-checks it: `if (m_EntryCount > (size - AP4_FULL_ATOM_HEADER_SIZE - 4)/4)`  
- Line 81-82: allocates `new AP4_UI32[m_EntryCount]` and `new unsigned char[m_EntryCount*4]`

`AP4_FULL_ATOM_HEADER_SIZE = 12` (confirmed in Ap4Atom.h:61). The `Create` factory method only checks `size < AP4_FULL_ATOM_HEADER_SIZE` (i.e., size < 12), so **size = 12, 13, 14, or 15 all pass** and reach the constructor. 

When size = 12: `(12u - 12u - 4u)` = `0u - 4u` = **0xFFFFFFFC** (unsigned underflow). The division gives `0xFFFFFFFC / 4 = 0x3FFFFFFF`. The effective guard becomes `if (m_EntryCount > 0x3FFFFFFF)` — which fails to clamp the value for any m_EntryCount ≤ 1 billion. An attacker sets m_EntryCount = 0x3FFFFFFF, triggering `new AP4_UI32[0x3FFFFFFF]` (≈4GB) and `new unsigned char[0xFFFFFFFC]` (≈4GB), both of which throw `std::bad_alloc` (uncaught) → crash.

The factory-level check at AtomFactory.cpp:215 only rejects size < 8 or size > bytes_available; size = 12 is a valid stco box per that check.

## VULN: Integer Underflow in stco Entry-Count Bounds Check Leading to Unconstrained Heap Allocation
- **漏洞类别**: memory-safety
- **函数**: AP4_StcoAtom::AP4_StcoAtom(AP4_UI32, AP4_UI08, AP4_UI32, AP4_ByteStream&)
- **行号**: 78-82
- **CWE**: CWE-191 (Integer Underflow (Wrap-Around)) → CWE-770 (Allocation of Resources Without Limits or Throttling)
- **CVSS v3.1**: 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_File::AP4_File() → AP4_AtomFactory::CreateAtomFromStream() → AP4_StcoAtom::Create(size_32=12, stream) → AP4_StcoAtom::AP4_StcoAtom(size=12, ..., stream) → unsigned underflow at line 78 → new AP4_UI32[0x3FFFFFFF] → std::bad_alloc → abort
- **描述**: 在私有解析构造函数中，第78行的边界检查使用无符号减法 `(size - AP4_FULL_ATOM_HEADER_SIZE - 4)` 计算允许的最大 entry_count。当 `size` 为 12（即等于 `AP4_FULL_ATOM_HEADER_SIZE = 12`）时，`12u - 12u - 4u = 0u - 4u = 0xFFFFFFFC`（无符号下溢），除以4后得到 0x3FFFFFFF。因此边界检查变为 `if (m_EntryCount > 0x3FFFFFFF)`，只要 m_EntryCount ≤ 10亿均不被截断。随后 `new AP4_UI32[m_EntryCount]` 和 `new unsigned char[m_EntryCount*4]` 最多分配约4GB内存，触发 std::bad_alloc（异常未被捕获），导致进程崩溃。`Create()` 方法仅检查 `size < AP4_FULL_ATOM_HEADER_SIZE`（即 < 12），而最小合法的 stco 全箱（含 entry_count 字段）需要16字节，漏掉了 size = 12..15 的情况。
- **触发条件**: 构造一个 stco box，其 box size 字段设为 12（或 13、14、15），紧随其后的4字节（被当作 entry_count 解析）设为 0x3FFFFFFF（或更大），即可绕过边界检查，触发约4GB的堆分配。
- **安全影响**: 进程因未捕获的 std::bad_alloc 异常崩溃，造成拒绝服务（DoS）。在将 MP4 处理集成到服务端自动处理管道的场景中（如媒体转码服务），攻击者可通过上传单个精心构造的 MP4 文件使服务持续崩溃。

<!-- AUDIT_PROMPT_VERSION: 1 -->
