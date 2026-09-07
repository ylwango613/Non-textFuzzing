Now I have all the context I need. Let me analyze the findings:

**Key issues found:**

1. **`ReadCache()` (Ap4Utils.cpp:430)** — NO bounds check. It accesses `m_Buffer.GetData() + m_Position` and reads 4 bytes without checking `m_Position + 4 <= buffer_size`. Once `m_Position` exceeds the buffer, this is a heap OOB read.

2. **Constructor (line 76)** initializes `AP4_BitReader bits(payload, payload_size)` with the true size, but then the loop at line 113-176 iterates `n_presentations` (up to 511 from 9 file-controlled bits) times, reading many bits per iteration. With a minimal 11-byte payload (minimum to pass line 73's sanity check) and `n_presentations=511`, the reads at lines 101-103 (`bit_rate` = 32 bits, `bit_rate_precision` = 32 bits) already push past the buffer boundary, and the 511-iteration loop massively overshoots.

3. **Integer underflow at line 49**: `size - AP4_ATOM_HEADER_SIZE` where `size` is file-controlled; no guard for `size < 8`.

## VULN: Heap OOB Read via AP4_BitReader Unchecked ReadCache in dac4 DSI Parsing
- **漏洞类别**: memory-safety
- **函数**: AP4_Dac4Atom::AP4_Dac4Atom() / AP4_BitReader::ReadCache()
- **行号**: 76-176 (Ap4Dac4Atom.cpp); 430-434 (Ap4Utils.cpp)
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac input.mp4 → AP4_File/AP4_AtomFactory parses "dac4" box → AP4_Dac4Atom::Create(size, stream) → AP4_Dac4Atom::AP4_Dac4Atom(size, payload) [line 56] → AP4_BitReader bits(payload, payload_size) [line 76] → bits.ReadBits() [lines 101-103, 113-175] → AP4_BitReader::ReadBits() → AP4_BitReader::ReadCache() [Ap4Utils.cpp:430] reads 4 bytes at m_Buffer.GetData()+m_Position with no bounds check
- **描述**: `AP4_BitReader::ReadCache()` (Ap4Utils.cpp:430-434) reads a 4-byte word at `m_Buffer.GetData() + m_Position` via four consecutive pointer dereferences (`out_ptr[0..3]`) with no check that `m_Position + 4 <= m_Buffer.GetDataSize()`. In `AP4_Dac4Atom`'s constructor, when `ac4_dsi_version == 1`, `n_presentations` is read from 9 file-controlled bits (max 511), and the constructor allocates `new PresentationV1[n_presentations]` then loops 511 times reading dozens of bits per iteration. The payload buffer is bounded by the actual box payload (minimum 11 bytes to pass the sanity check at line 73). The reads for `bit_rate` (32 bits) and `bit_rate_precision` (32 bits) at lines 101-103 consume bits 26-89, already exceeding an 88-bit (11-byte) payload, and the 511-iteration presentation parsing loop drives `m_Position` massively past the end of the heap buffer, producing a multi-kilobyte heap OOB read.
- **触发条件**: 构造 MP4 文件，其中 `dac4` box 的 payload 仅 11 字节（恰好通过第 73 行的 sanity check），同时设置 `ac4_dsi_version=1`、`bitstream_version≤1`（跳过可选字段）、`n_presentations=511`（9-bit 字段全置 1）。BitReader 从仅 88 bit 的缓冲区中试图读取数万 bit，ReadCache() 在无任何边界检查的情况下持续向后越界读取堆内存。
- **安全影响**: 堆越界读取可泄露相邻堆块内容（堆元数据、其它 box 解析数据、指针值），可辅助绕过 ASLR，构成信息泄露；若越界读命中未映射页（依赖堆布局），触发 SIGSEGV 导致进程崩溃（DoS）。在精心控制堆布局的场景下，泄露的指针值可进一步链式利用，最坏情况下可达 RCE。

## VULN: Integer Underflow in AP4_Dac4Atom::Create Leading to Oversized Heap Allocation
- **漏洞类别**: memory-safety
- **函数**: AP4_Dac4Atom::Create()
- **行号**: 49-51
- **CWE**: CWE-191 (Integer Underflow / Wraparound)
- **CVSS v3.1**: 5.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac input.mp4 → AP4_AtomFactory parses "dac4" box with file-supplied size field < 8 → AP4_Dac4Atom::Create(size, stream) [line 49]: `unsigned int payload_size = size - AP4_ATOM_HEADER_SIZE` underflows → AP4_DataBuffer payload_data(payload_size) allocates ~4 GB → std::bad_alloc / OOM crash
- **描述**: 第 49 行 `unsigned int payload_size = size - AP4_ATOM_HEADER_SIZE`（AP4_ATOM_HEADER_SIZE=8），`size` 直接来自 MP4 文件中的 box size 字段（AP4_UI32），在减法前没有任何 `size >= 8` 的前置校验。当 MP4 文件将 dac4 box 的 size 设为小于 8 的值（例如 4 或 0）时，无符号减法产生下溢，`payload_size` 变为约 0xFFFFFFF8（4,294,967,288）。随后第 50 行 `AP4_DataBuffer payload_data(payload_size)` 尝试在堆上分配约 4 GB 内存，触发 `std::bad_alloc` 或系统 OOM，若异常未被上层捕获则导致进程崩溃。
- **触发条件**: 构造 MP4 文件，将 `dac4` box 的 4 字节 size 字段设置为任意小于 8 的值（例如 0x00000004 或 0x00000001）。
- **安全影响**: 进程因 OOM/bad_alloc 崩溃，导致拒绝服务（DoS）。若 Bento4 在调用 Create() 前已在 AtomFactory 层对 size 做了 ≥8 的校验则此漏洞不可达，但代码本身无此防护。

<!-- AUDIT_PROMPT_VERSION: 1 -->
