Now I have enough context. Let me analyze the key vulnerability.

**Analysis of Ap4OdheAtom.cpp constructor (lines 60-77):**

- `AP4_Size` = `AP4_UI32` (unsigned 32-bit)
- Guard in `Create()` (line 51): only checks `size < AP4_FULL_ATOM_HEADER_SIZE` (i.e., size < 12)
- Constructor (line 75): `AP4_Size bytes_available = size-(AP4_FULL_ATOM_HEADER_SIZE+1+content_type_length)`
  - `AP4_FULL_ATOM_HEADER_SIZE` = 12, plus 1-byte length field, plus `content_type_length` (0–255 from `AP4_UI08`)
  - Minimum subtrahend = 13, maximum = 268
  - With size=12 (minimum allowed by guard) and content_type_length=1: `bytes_available = 12 - 14 = 0xFFFFFFFE` (wraps around)
- This wraps to ~4 GB when widened to `AP4_UI64` and passed to `ReadChildren`
- `CreateAtomFromStream` check (Ap4AtomFactory.cpp:215): `size > bytes_available` — with bytes_available ≈ 4 GB, child atoms claiming sizes up to 4 GB pass unchecked
- Child atoms can then be parsed beyond the odhe atom's claimed boundary (reading sibling atom data), or allocate large buffers leading to heap exhaustion/OOB reads

## VULN: Integer Underflow in bytes_available Leads to OOB Read in OdheAtom
- **漏洞类别**: memory-safety
- **函数**: AP4_OdheAtom::AP4_OdheAtom()
- **行号**: 75-76
- **CWE**: CWE-191 (Integer Underflow) → CWE-125 (Out-of-Bounds Read)
- **CVSS v3.1**: 7.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac input.mp4 → AP4_File::Parse() → AP4_AtomFactory::CreateAtomFromStream() → AP4_OdheAtom::Create() → AP4_OdheAtom::AP4_OdheAtom(constructor) → ReadChildren(atom_factory, stream, bytes_available)
- **描述**: 在 `AP4_OdheAtom` 构造函数第75行，计算 `bytes_available = size - (AP4_FULL_ATOM_HEADER_SIZE + 1 + content_type_length)`。`size` 为 `AP4_UI32`（来自文件），`AP4_FULL_ATOM_HEADER_SIZE`=12，加上1字节长度字段和 `content_type_length`（`AP4_UI08`，0-255），最小合法减数为13。而 `Create()` 中的护卫仅检查 `size < 12`，允许 size=12 进入构造函数。当 size=12 且 content_type_length≥1 时，`12 - 14` 等无符号下溢，`bytes_available` 环绕为约 `0xFFFFFFFE`（~4 GB）。该值被隐式拓宽为 `AP4_UI64` 后传递给 `ReadChildren`，进而传递给 `CreateAtomFromStream`；其中的大小边界检查 `size > bytes_available`（Ap4AtomFactory.cpp:215）实际上失效，允许后续子 atom 以超过 odhe atom 声明大小的大小值被解析，造成流的跨边界越界读取（读取下一个兄弟 atom 的字节作为子 atom 数据），或触发子 atom 构造函数按虚高大小分配堆内存（大内存申请）。
- **触发条件**: 构造一个 `odhe` atom，令其 `size` 字段（文件中的4字节大端整数）= 12（即 `AP4_FULL_ATOM_HEADER_SIZE`，仅能通过 Create() 的护卫检查），并令随后读取的 `content_type_length` 字节 ≥ 1（例如设为255），从而使 `12 - (12+1+255) = -256` 无符号下溢至 `0xFFFFFF00`，作为子 atom 解析预算传入 ReadChildren。
- **安全影响**: 越界读取可导致进程崩溃（DoS），或读取相邻内存/流数据，造成内存内容泄露；若下游子 atom 解析器依赖失控的 bytes_available 执行堆分配（如 `AP4_UnknownAtom` 分配巨型缓冲区），则可进一步导致堆耗尽或堆缓冲区溢出，最坏情况下可远程代码执行（RCE）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
