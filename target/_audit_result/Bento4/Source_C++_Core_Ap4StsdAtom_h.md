Based on my analysis of `Ap4StsdAtom.h`, `Ap4StsdAtom.cpp`, `Ap4Array.h`, `Ap4Atom.h`, `Ap4AtomFactory.cpp`, and related types, I've identified the following memory-safety finding:

**Group 1 (Ap4StsdAtom.cpp:98)**: `bytes_available = size - AP4_FULL_ATOM_HEADER_SIZE - 4` — `AP4_FULL_ATOM_HEADER_SIZE = 12`, so the constructor subtracts 16 from `size`. `Create()` only enforces `size >= 12` (not `>= 16`). When `size ∈ {12,13,14,15}`, unsigned 32-bit arithmetic wraps to `0xFFFFFFFC`–`0xFFFFFFFF`, then widens to a ~4 GB `AP4_LargeSize`. The inflated `bytes_available` is passed verbatim to the `CreateAtomFromStream` loop, allowing child atoms whose declared size significantly exceeds the stsd box boundary to pass the guard at line 215 (`size > bytes_available`). The parser therefore reads stream bytes from outside the stsd box, treating them as child sample entries — a confirmed out-of-bounds stream read that can escalate to heap allocation from attacker-controlled data depending on which atom handler is invoked.

**Group 2 (Ap4StsdAtom.cpp:172)**: `m_SampleDescriptions[index]` is accessed via a bounds-unchecked `AP4_Array::operator[]`. The bounds guard at line 169 uses `m_Children.ItemCount()`. The invariant `m_SampleDescriptions.ItemCount() == m_Children.ItemCount()` holds only at construction; `OnChildAdded`/`OnChildRemoved` are not overridden, so any external `AddChild`/`RemoveChild` call on an `AP4_StsdAtom` object silently breaks the invariant and makes line 172 an OOB heap read. In the direct mp42aac parsing path this invariant is not violated, so this finding is secondary.

## VULN: Integer Underflow in bytes_available Enables Out-of-Bounds Stream Read and Heap Corruption
- **漏洞类别**: memory-safety
- **函数**: AP4_StsdAtom::AP4_StsdAtom(AP4_UI32, AP4_UI08, AP4_UI32, AP4_ByteStream&, AP4_AtomFactory&)
- **行号**: 98-109
- **CWE**: CWE-191 (Integer Underflow) → CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.1 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: `mp42aac` → `AP4_File::AP4_File` → `AP4_MoovAtom` → `AP4_TrakAtom` → `AP4_MdiaAtom` → `AP4_MinfAtom` → `AP4_StblAtom` → `AP4_StsdAtom::Create(size=12..15, stream, factory)` → `AP4_StsdAtom::AP4_StsdAtom(AP4_UI32 size, ...)` line 98
- **描述**: `Create()` 只检查 `size < AP4_FULL_ATOM_HEADER_SIZE (12)` 便放行（Ap4StsdAtom.cpp:54），而构造函数在 line 98 计算 `bytes_available = size - 12 - 4`，全程以 `AP4_UI32` 无符号运算完成：当 `size ∈ {12,13,14,15}` 时，`size-12 ∈ {0,1,2,3}`，再减 4 回绕为 `0xFFFFFFFC`–`0xFFFFFFFF`，赋值到 64 位 `AP4_LargeSize` 得约 4 GB。该值传入 `atom_factory.CreateAtomFromStream(stream, bytes_available, atom)` 循环；其内部的 `size > bytes_available` 守卫（Ap4AtomFactory.cpp:215）对任何 ≤ 4 GB 的子 atom 声明大小均判定为合法，从而允许解析器读取远超 stsd atom 实际边界的流数据。被错误当作子 sample entry 解析的字节可能属于相邻 box（如 `esds`/`avc1`），驱动对应 atom handler 以攻击者控制的字段执行堆分配，造成堆损坏或敏感数据泄露。
- **触发条件**: 构造一个 `stsd` box，其 4 字节 size 字段值为 12、13、14 或 15（即 box 头部刚好或几乎等于 `AP4_FULL_ATOM_HEADER_SIZE`），紧跟任意字节（这些字节会被当作 entry_count 和子 atom 数据读取）。用该 MP4 文件运行 `mp42aac input.mp4 output.aac` 即可触发。
- **安全影响**: 解析器读取 stsd 边界以外的堆/文件数据（越界读，信息泄漏）；如相邻 atom handler 根据攻击者控制的字段执行堆分配或写操作，可进一步升级为堆破坏，最坏情况下导致 RCE；退化场景为进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
