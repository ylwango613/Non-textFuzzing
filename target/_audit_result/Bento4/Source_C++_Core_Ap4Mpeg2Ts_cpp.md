I now have a complete picture of the file. Let me synthesize my multi-pass analysis findings:

**Pass 1 (lines 0-600) key observations:**
- Line 444: `new unsigned char[7+sample_data.GetDataSize()]` – allocation, but ReadData sets data size = sample.GetSize() so they're equal; on 32-bit only with a ~4GB stsz entry could this overflow, but ReadData would fail (bad_alloc) before reaching line 444 on any realistic platform.
- Line 448: `WritePES(buffer, 7+sample.GetSize(), ...)` – same value, no mismatch.

**Pass 2 (lines 600-946) key observations:**
- `WritePMT` (lines 797-866): `section_length` is computed as `13 + 5 + audio_desc_size + 5 + video_desc_size` with **no upper bound check**. `AP4_BitWriter writer(1024)` has overflow protection (silently drops bits past 1024 bytes), but the two `output.Write` calls after do NOT respect that cap:
  - Line 862: `output.Write(writer.GetData(), section_length+4)` – reads `section_length+4` bytes from the 1024-byte heap buffer. OOB heap read when `section_length+4 > 1024`.
  - Line 863: `output.Write(StuffingBytes, AP4_MPEG2TS_PACKET_PAYLOAD_SIZE-(section_length+4))` = `184 - (section_length+4)`. When `section_length+4 > 184` (i.e., combined descriptor > 157 bytes), **unsigned integer underflow** to ~UINT_MAX, causing an attempt to read ~4 GB from the 188-byte static `StuffingBytes` array → crash.
  - Line 860: `ComputeCRC(writer.GetData()+1, section_length-1)` also reads `section_length-1` bytes from the 1024-byte buffer when `section_length > 1024`.

**Root cause for both**: No bounds check on `section_length` relative to either the 1024-byte `AP4_BitWriter` buffer or the 184-byte `AP4_MPEG2TS_PACKET_PAYLOAD_SIZE` constraint.

**Trigger**: A crafted MP4 with a large codec-specific descriptor box (e.g., `esds` for AAC > 158 bytes total) passed through a Bento4 MPEG-TS conversion tool's `SetAudioStream`/`SetVideoStream` call chain.

---

## VULN: WritePMT Unsigned-Integer Underflow → OOB Read Crash via Large PMT Descriptor
- **漏洞类别**: memory-safety
- **函数**: AP4_Mpeg2TsWriter::WritePMT()
- **行号**: 810-863
- **CWE**: CWE-191 (Integer Underflow) / CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 6.5 (AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: crafted MP4 file → Bento4 MPEG-TS conversion tool (mp42ts / library user) → AP4_Mpeg2TsWriter::SetAudioStream()/SetVideoStream() stores large descriptor → AP4_Mpeg2TsWriter::WritePMT() → `section_length = 13 + 5 + m_Audio->m_Descriptor.GetDataSize() + 5 + m_Video->m_Descriptor.GetDataSize()` exceeds 180 → `AP4_MPEG2TS_PACKET_PAYLOAD_SIZE - (section_length+4)` = `184 - (section_length+4)` underflows unsigned → `output.Write(StuffingBytes, ~0U)` reads ~4 GB from 188-byte static array
- **描述**: `WritePMT` computes `section_length` as the sum of audio and video descriptor sizes plus a fixed header overhead (23 bytes), with no upper-bound validation. The function allocates only a fixed 1024-byte `AP4_BitWriter writer` and a constant 188-byte static `StuffingBytes` array. At line 863, `output.Write(StuffingBytes, AP4_MPEG2TS_PACKET_PAYLOAD_SIZE-(section_length+4))` performs an unsigned subtraction `184 - (section_length+4)`. When the combined descriptor size exceeds 157 bytes (making `section_length+4 > 184`), the subtraction wraps to approximately `UINT_MAX - (section_length+4-184)`, and `output.Write` attempts to read that many bytes from the 188-byte `StuffingBytes` static array, accessing far out-of-bounds memory.
- **触发条件**: 攻击者构造 MP4 文件，使其 `esds`（AAC codec-specific info）或 `avcC`（AVC decoder config）描述符总长超过 158 字节（单独音频或视频描述符即可），触发 `section_length+4 > 184`，从而导致无符号整数下溢。
- **安全影响**: 进程因访问越界静态内存（超出 188 字节 StuffingBytes 数组）而崩溃（SIGSEGV），造成拒绝服务（DoS）。若 `output.Write` 底层实现在读取时顺序遍历内存，还可能泄露进程地址空间中的相邻静态数据。

## VULN: WritePMT Out-of-Bounds Heap Read via Oversized PMT Descriptor (Heap Info Leak)
- **漏洞类别**: memory-safety
- **函数**: AP4_Mpeg2TsWriter::WritePMT()
- **行号**: 808-862
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 5.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:L)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: crafted MP4 file → Bento4 MPEG-TS conversion tool → SetAudioStream()/SetVideoStream() with descriptor_length > 997 bytes (from MP4 codec box) → WritePMT() → `AP4_BitWriter writer(1024)` heap buffer allocated at line 808 → `section_length = 23 + descriptor_sizes > 1020` → `output.Write(writer.GetData(), section_length+4)` at line 862 reads `section_length+4 > 1024` bytes from 1024-byte heap allocation → OOB heap read; `ComputeCRC(writer.GetData()+1, section_length-1)` at line 860 also reads `section_length-1 > 1023` bytes from same buffer
- **描述**: `WritePMT` 在栈上创建固定 1024 字节的 `AP4_BitWriter writer(1024)`（其内部 `new unsigned char[1024]`），然后将 `section_length+4` 字节写入输出流（line 862）：`output.Write(writer.GetData(), section_length+4)`。`AP4_BitWriter::Write` 会在超过 1024 字节后静默丢弃位写入，但 `output.Write` 的字节数参数直接使用 `section_length+4`，不受 BitWriter 缓冲区大小限制。当音视频描述符合计超过 997 字节时，`section_length+4 > 1024`，`output.Write` 和 `ComputeCRC` 均读取超出 1024 字节堆缓冲区的相邻堆内存，将其写入输出 TS 文件或用于 CRC 计算。
- **触发条件**: 攻击者构造 MP4 文件，使 `esds` / `avcC` / AC-3 描述符总长超过 997 字节，驱动 Bento4 库对应工具调用 `SetAudioStream`/`SetVideoStream`，随后调用 `WritePMT`。
- **安全影响**: 越界读取堆内存并将其内容输出到生成的 MPEG-TS 文件中，泄露相邻堆对象数据（堆信息泄露）；若配合堆布局控制可辅助 RCE 利用。同时 `ComputeCRC` 读取越界数据可能导致进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
