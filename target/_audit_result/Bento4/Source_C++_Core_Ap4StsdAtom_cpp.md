I now have a complete picture. Here is my full analysis:

**File summary (223 lines, fully read):**

- `Create()` (line 47–58): guards `size < AP4_FULL_ATOM_HEADER_SIZE` (i.e., `size < 12`) then calls the parsing constructor.
- Parsing constructor (line 83–119): reads `entry_count` from stream (4 bytes), then computes `bytes_available = size - AP4_FULL_ATOM_HEADER_SIZE - 4` on line 98.
- `AP4_LargeSize` = `uint64_t`; `AP4_Size` = `AP4_UI32` = `uint32_t`; `AP4_FULL_ATOM_HEADER_SIZE` = 12 (`const AP4_UI32`).

**Critical finding — integer underflow on line 98:**

The guard only ensures `size >= 12`, but `bytes_available` subtracts 16 total (`12 + 4`). When `size ∈ {12, 13, 14, 15}`, the `AP4_UI32` subtraction wraps to `≈ 0xFFFFFFFC–0xFFFFFFFF`, then is zero-extended to the `uint64` `bytes_available`. The `CreateAtomFromStream` guard `size > bytes_available` (line 215 of `Ap4AtomFactory.cpp`) never triggers, so the factory reads far beyond the stsd box boundary. Additionally, `stream.ReadUI32(entry_count)` at line 92 has already consumed 4 bytes beyond the declared box boundary when `size < 16`.

No other memory-safety bugs were found in this 223-line file (destructor, `GetSampleDescription`, `GetSampleEntry`, `WriteFields`, `OnChildChanged` all either have correct bounds checks or operate on already-validated data).

## VULN: Integer Underflow in bytes_available Allows Out-of-Bounds Stream Read
- **漏洞类别**: memory-safety
- **函数**: AP4_StsdAtom::AP4_StsdAtom(AP4_UI32, AP4_UI08, AP4_UI32, AP4_ByteStream&, AP4_AtomFactory&)
- **行号**: 98-108
- **CWE**: CWE-191 (Integer Underflow) → CWE-125 (Out-of-Bounds Read)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: `mp42aac input.mp4` → `AP4_File::AP4_File()` → `AP4_AtomFactory::CreateAtomFromStream()` → `AP4_StsdAtom::Create(size=12..15, stream, factory)` → `AP4_StsdAtom::AP4_StsdAtom(size, version, flags, stream, factory)` → line 98: `bytes_available = size - AP4_FULL_ATOM_HEADER_SIZE - 4` (AP4_UI32 underflow)
- **描述**: `Create()`（Ap4StsdAtom.cpp:54）仅检查 `size < AP4_FULL_ATOM_HEADER_SIZE`（即 `size < 12`），但未检查 `size < 16`。构造函数第 98 行以 `AP4_UI32` 算术计算 `size - 12 - 4`：当 `size ∈ {12,13,14,15}` 时，减法在无符号 32 位域下向下溢出，得到约 `0xFFFFFFFC`，随后零扩展为 64 位 `AP4_LargeSize bytes_available ≈ 0xFFFFFFFC`。同时，第 92 行 `stream.ReadUI32(entry_count)` 已读取盒子声明末尾之外的 4 个字节。在这两个问题叠加下，`atom_factory.CreateAtomFromStream` 的 `size > bytes_available` 检查形同虚设，解析器可无限制地将 stsd 盒子之后的任意文件数据当作 stsd 子 atom 进行解析，造成堆外越界读取；若后续被解析的攻击者构造的"子 atom"携带任意大小字段，可进一步触发下游（如 `AP4_Mp4aSampleEntry` 等）的错误大小分配，escalate 至堆破坏。
- **触发条件**: 在 MP4 文件的 moov/trak/mdia/minf/stbl/ 路径下构造一个 stsd box，将其 size 字段设置为 12、13、14 或 15（例如 `00 00 00 0C 73 74 73 64 00 00 00 00`，size=12），并在其后紧跟精心构造的伪 atom 数据（控制类型、大小字段），即可在无任何特权的情况下由攻击者完全控制被越界解析的内容。
- **安全影响**: 最坏情况下，攻击者通过控制越界读取的内容并驱动下游 sample-entry 解析器（如 `AP4_Mp4aSampleEntry`）使用攻击者指定的大小分配堆缓冲区，可实现堆破坏，进而导致任意代码执行（RCE）；保守估计至少可实现进程崩溃（DoS）和越界内存泄露（信息泄露）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
