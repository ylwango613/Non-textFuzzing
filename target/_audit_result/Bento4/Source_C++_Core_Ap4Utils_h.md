I now have enough context to write my final report. The complete analysis:

**Group 1 — `AP4_BitWriter` (lines 218–240 in Ap4Utils.h, impl lines 322–342 in Ap4Utils.cpp):**
- Constructor `AP4_BitWriter(size)` with hardcoded sizes in all callers (23, 1024, etc.) — not file-controlled.
- The `Write()` guard `m_BitCount+bit_count > m_DataSize*8` has a theoretical 32-bit wrap but is not reachable via file-controlled sizes.
- **No exploitable path from mp42aac.**

**Group 2 — `AP4_BitReader` (lines 245–276 in Ap4Utils.h, impl lines 382–566 in Ap4Utils.cpp):**
- `ReadCache()` (line 428): reads 4 bytes at `m_Buffer.GetData() + m_Position` with **zero bounds checking**.
- `ReadBit()`, `ReadBits()`, `PeekBit()`, `PeekBits()`, `SkipBit()`, `SkipBits()` all call `ReadCache()` without checking that `m_Position < m_Buffer.GetBufferSize()`.
- Buffer is allocated as `4 × ⌈data_size/4⌉` bytes (zero-padded to word boundary). For `data_size = 11`, buffer = 12 bytes. After consuming 12 bytes of bits, any further read triggers OOB at `m_Buffer.GetData() + 12`.

**Call chain to `AP4_BitReader`:**
- `mp42aac` → MP4 box parser → `AP4_AtomFactory.cpp:721` dispatches `dac4` box → `AP4_Dac4Atom::Create()` (reads `payload_size = size − 8` bytes from stream) → `new AP4_Dac4Atom(size, payload)` → constructor line 76: `AP4_BitReader bits(payload, payload_size)`.
- Sanity check at line 73 only requires `payload_size >= 11`.
- With 11-byte payload: parses 3+7+1+4+9=24 bits (v1 header) + 66 bits for bit_rate_dsi (2+32+32) = 90 bits before byte-align, then loops over `n_presentations` (0-511, file-controlled, read at line 90). By the time `bit_rate_precision` (32 bits) is read, total is 90+ bits > 96 bits (12 bytes available) → **fourth `ReadCache()` call reads from `m_Buffer.GetData() + 12`, 4 bytes past the end of the 12-byte allocation** → confirmed heap buffer overread.

## VULN: AP4_BitReader ReadCache Heap OOB Read via dac4 Box
- **漏洞类别**: memory-safety
- **函数**: AP4_BitReader::ReadCache()
- **行号**: 428-435 (Ap4Utils.cpp); 245-276 (Ap4Utils.h, class declaration)
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: `mp42aac input.mp4` → `AP4_AtomFactory::CreateAtomFromStream()` (Ap4AtomFactory.cpp:721, case AP4_ATOM_TYPE_DAC4) → `AP4_Dac4Atom::Create(size, stream)` (Ap4Dac4Atom.cpp:46) → `new AP4_Dac4Atom(size, payload)` (Ap4Dac4Atom.cpp:56) → `AP4_BitReader bits(payload, payload_size)` (Ap4Dac4Atom.cpp:76) → `bits.ReadBits(32)` for `bit_rate_precision` field (Ap4Dac4Atom.cpp:103) → `AP4_BitReader::ReadBits()` (Ap4Utils.cpp:441) → `AP4_BitReader::ReadCache()` (Ap4Utils.cpp:428) → `out_ptr[0..3]` where `out_ptr = m_Buffer.GetData() + m_Position` and `m_Position >= m_Buffer.GetBufferSize()`
- **描述**: `AP4_BitReader::ReadCache()`（Ap4Utils.cpp:428–435）每次从 `m_Buffer.GetData() + m_Position` 处读取 4 字节，但既不检查 `m_Position` 是否超出缓冲区末尾，也没有 EOF 标志机制。所有读取/跳过方法（`ReadBit`、`ReadBits`、`PeekBit`、`PeekBits`、`SkipBit`、`SkipBits`）都不带边界检查地调用 `ReadCache()`。在 `Ap4Dac4Atom.cpp` 中，`payload_size` 最小为 11 字节（第 73 行 sanity check），对应 `AP4_BitReader` 缓冲区实际分配 12 字节（向上对齐到 4 字节的倍数）。攻击者可将 `ac4_dsi_version=1`、`bitstream_version=2`、`n_presentations=511` 等字段编码到 11 字节的 `dac4` 载荷中，解析 `bit_rate_precision`（第 103 行，32 位）时累计读取超过 96 bit（12 字节），触发 `ReadCache()` 在 `m_Buffer.GetData() + 12` 处读取超出堆缓冲区边界的 4 字节，造成堆越界读。
- **触发条件**: 在 MP4 文件中构造一个 `dac4` box，令 `size = 8 + 11`（payload_size = 11 字节，恰好通过 `>= 11` 检查），并将 11 字节的 payload 编码为：`ac4_dsi_version = 1`（3 bits），`bitstream_version = 2`（7 bits），`fs_index`（1 bit），`frame_rate_index`（4 bits），`n_presentations = 511`（9 bits），`b_program_id = 0`（1 bit），`bit_rate_mode`（2 bits），`bit_rate`（32 bits），到 `bit_rate_precision` 时累计需要 ≥ 97 bits，超过 12 字节缓冲区。
- **安全影响**: 堆越界读取最多数十字节的堆内存内容，可泄露堆布局信息（辅助 ASLR 绕过）；同时在 ASAN/严格配置下或越界地址不可读时导致进程崩溃（DoS）。在精细堆喷射配合下，理论上可将堆布局信息与后续漏洞链组合实现更高危利用。

<!-- AUDIT_PROMPT_VERSION: 1 -->
