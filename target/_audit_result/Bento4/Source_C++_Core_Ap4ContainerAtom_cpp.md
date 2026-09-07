I now have all the context needed to write the final report. The analysis is complete.

**Key finding**: In `AP4_ContainerAtom.cpp`, the size guard in `Create()` (line 57) uses `AP4_FULL_ATOM_HEADER_SIZE = 12` for ALL full atoms, but for a 64-bit full atom the actual header is 20 bytes (`AP4_FULL_ATOM_HEADER_SIZE_64 = 20`). The constant `AP4_FULL_ATOM_HEADER_SIZE_64` exists in `Ap4Atom.h` line 62 but is never used in the guard. So a crafted 64-bit META/ODRM/ODKM atom with declared size 12–19 passes the check, but `size - GetHeaderSize()` (line 154) underflows as `AP4_UI64` arithmetic (e.g., `14 - 20 = 0xFFFFFFFFFFFFFFFA`). This passes a near-maximal `bytes_available` to `ReadChildren`, causing the parser to read far beyond the atom's declared boundary as child atoms.

The second sub-path is `MARL` at top level (Ap4AtomFactory.cpp line 768–772): there is no `atom_is_large` guard, so a 64-bit non-full MARL with size 8–15 hits the same underflow in the non-full constructor (line 139), where `GetHeaderSize() = 16` for a 64-bit atom.

---

## VULN: Integer Underflow in ReadChildren via Crafted 64-bit Full/Non-full Container Atom Size
- **漏洞类别**: memory-safety
- **函数**: AP4_ContainerAtom::AP4_ContainerAtom() / AP4_ContainerAtom::Create()
- **行号**: 57 (guard), 139, 154 (underflow site)
- **CWE**: CWE-191 (Integer Underflow) → CWE-125 (Out-of-Bounds Read)
- **CVSS v3.1**: 7.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_File::AP4_File(stream) → AP4_AtomFactory::CreateAtomFromStream(stream, bytes, atom) → AP4_AtomFactory::CreateAtomFromStream(stream, type, size_32=1, size_64=14, atom) → AP4_ContainerAtom::Create(META, size=14, is_full=true, force_64=true, stream, factory) → AP4_ContainerAtom::AP4_ContainerAtom(META, 14, true, version, flags, stream, factory) → ReadChildren(factory, stream, 14-20 /* AP4_UI64 underflow */)
- **描述**: `Create()` 在 line 57 检查 `if (size < AP4_FULL_ATOM_HEADER_SIZE) return NULL`，其中 `AP4_FULL_ATOM_HEADER_SIZE = 12`；但对于 64 位编码的 full 容器 atom，实际 header 大小为 `AP4_FULL_ATOM_HEADER_SIZE_64 = 20`（该常量已定义在 Ap4Atom.h:62 但未在此处使用）。当攻击者构造 64 位编码的 META/ODRM/ODKM atom，size_32=1 且 size_64∈[12,19] 时，12≤size<20 的检查通过，随后在 line 154 执行 `size - GetHeaderSize()` 时，两者均为无符号 64 位，`14 - 20` 等得 `0xFFFFFFFFFFFFFFFA`，发生 AP4_UI64 下溢。下溢后的巨型值被传入 `ReadChildren` 作为 `bytes_available`，导致 `CreateAtomFromStream` 的 `size > bytes_available` 边界检查永远不触发，解析器从当前流位置（已越过 atom 声明末尾）无限制地读取后续 sibling 数据当作子 atom，造成越界读。同理，对于顶层 MARL atom（Ap4AtomFactory.cpp line 768–772 无 `atom_is_large` 检查），64 位 MARL 且 size_64∈[8,15] 时非 full 路径（line 139）同样触发 `size - 16` 下溢。
- **触发条件**: 构造一个 MP4 文件，在顶层或合法父 atom 内放置 64 位编码（size_32=1）的 `meta`/`odrm`/`odkm` box，其 size_64 字段值设为 12–19（例如 0x000000000000000E），满足外层 `size >= 8` 检查和内层 `size >= AP4_FULL_ATOM_HEADER_SIZE(12)` 检查，但小于真实 64 位 full atom header 大小 20；或在文件顶层放置 64 位编码的 `marl` box，size_64∈[8,15]。
- **安全影响**: 解析器以近 2^64 的 `bytes_available` 在文件中越界遍历，把 sibling atom 的字节按序解析为子 atom。攻击者可通过在 crafted atom 后方放置特定二进制序列，使后续子 atom 解析器（如 stsz/stco）依据越界读到的伪造 count 字段进行大内存分配或访问非法内存，最终导致程序崩溃（DoS）或潜在的堆内存信息泄露；若后续 atom 解析路径含整数溢出 → 小分配 → 写溢出，则可升级至 RCE。

<!-- AUDIT_PROMPT_VERSION: 1 -->
