**Analysis summary:**

In `Ap4OdheAtom.cpp:75`:
```cpp
AP4_Size bytes_available = size-(AP4_FULL_ATOM_HEADER_SIZE+1+content_type_length);
```
- `AP4_Size` = `AP4_UI32` (unsigned 32-bit)
- `AP4_FULL_ATOM_HEADER_SIZE` = 12; the only guard in `Create()` is `size >= 12`
- With `size = 12` (minimum allowed) and `content_type_length = 0`, the subtraction is `12 - (12+1+0) = -1`, which wraps to `0xFFFFFFFF`
- That value is passed to `ReadChildren(…, AP4_UI64 size)`, widened to `0x00000000FFFFFFFF` (~4 GB)
- `CreateAtomFromStream` in ReadChildren uses `bytes_available` as the cap; with a ~4 GB cap it parses atoms far beyond the intended odhe atom boundary, treating attacker-controlled file data after the atom as `odhe` children
- Each of those "phantom children" feeds into further atom parsers (including allocation-heavy ones) with attacker-controlled sizes

Additionally, the return value of `stream.ReadUI08(content_type_length)` at line 69 is not checked; if the stream fails, `content_type_length` is indeterminate, making the underflow unpredictable.

## VULN: Integer Underflow in AP4_OdheAtom bytes_available Leading to OOB Parsing
- **漏洞类别**: memory-safety
- **函数**: AP4_OdheAtom::AP4_OdheAtom()
- **行号**: 75-76 (Ap4OdheAtom.cpp)
- **CWE**: CWE-191 (Integer Underflow / Wraparound)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_File::AP4_File() → AP4_AtomFactory::CreateAtomFromStream() → AP4_OdheAtom::Create() → new AP4_OdheAtom(size, version, flags, stream, atom_factory) → bytes_available underflow → ReadChildren() → further atom parsing with inflated byte budget
- **描述**: `AP4_OdheAtom` 的解析构造函数（Ap4OdheAtom.cpp:75）计算剩余字节数时执行 `AP4_Size bytes_available = size-(AP4_FULL_ATOM_HEADER_SIZE+1+content_type_length)`，其中 `AP4_Size` 为无符号 32 位类型。`Create()` 中仅做了 `size >= AP4_FULL_ATOM_HEADER_SIZE(12)` 的最低边界检查，未验证 `size >= 12+1+content_type_length`。当攻击者令 `size=12`、`content_type_length=0`（或 `content_type_length` 较大而 size 较小）时，减法结果为负，以无符号语义回绕为 `0xFFFFFFFF`（约 4 GB）。该值作为 `AP4_UI64` 传入 `ReadChildren()`，`CreateAtomFromStream` 据此认为有 ~4 GB 可用字节，从而在 `odhe` atom 边界之外继续解析攻击者控制的文件数据，将其视为合法的 odhe 子 atom，并对每个"幻影子 atom"调用相应的分配和解析逻辑，可能触发后续 atom 解析器中的堆分配越界写或读。
- **触发条件**: 构造一个 MP4 文件，其中包含 `odrm` 容器内的 `odhe` atom，令 `odhe` atom 头中声明的 size 字段为 12（或其他 `< AP4_FULL_ATOM_HEADER_SIZE+1+content_type_length` 的值），使 `bytes_available` 发生无符号下溢；在 `odhe` atom 之后紧跟攻击者精心构造的假 child atom 数据（携带大 size 字段或触发下游解析器漏洞的 payload）。
- **安全影响**: 解析器在 `odhe` atom 边界之外读取并处理攻击者控制的文件数据，可触发下游 atom 解析器的堆缓冲区溢出或大额堆分配，最坏情况下可导致远程代码执行（RCE）；至少可造成进程崩溃（DoS）或越界信息泄露。

<!-- AUDIT_PROMPT_VERSION: 1 -->
