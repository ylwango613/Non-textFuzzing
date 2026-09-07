I have now completed a full systematic audit of `Ap4Mpeg2Ts.h` and its implementation file `Ap4Mpeg2Ts.cpp`, along with callers in `Mp42Ts.cpp`, `Mp42Hls.cpp`, and the supporting data-buffer/sample primitives. Here is the final report with confirmed memory safety findings only.

## VULN: Integer Overflow in Audio Sample Buffer Allocation Leading to Heap Buffer Overflow
- **漏洞类别**: memory-safety
- **函数**: AP4_Mpeg2TsAudioSampleStream::WriteSample()
- **行号**: 445-449
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-787 (Out-of-bounds Write)
- **CVSS v3.1**: 7.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42ts input.mp4 output.ts → WriteSamples() → SampleStream::WriteSample(sample, sample_description, ...) [Ap4Mpeg2Ts.cpp:930] → sample.ReadData(sample_data) with m_Size from stsz/trun box → AP4_Mpeg2TsAudioSampleStream::WriteSample(sample, sample_data, ...) [line 409] → `new unsigned char[7+sample_data.GetDataSize()]` [line 445]
- **描述**: `sample_data.GetDataSize()` 返回 `AP4_UI32`（来自 MP4 stsz/trun box 的样本大小字段）。表达式 `7 + sample_data.GetDataSize()` 为无符号 32 位加法：当 `sample_data.GetDataSize() >= 0xFFFFFFF9` 时发生整数溢出，`new unsigned char[0..6]` 仅分配 0–6 字节的微型堆缓冲区。随后 `MakeAdtsHeader(buffer, sample_data.GetDataSize(), ...)` 向 `buffer[0..6]` 写入 7 字节（若 buffer 为 0 字节则立即越界），`AP4_CopyMemory(buffer+7, sample_data.GetData(), sample_data.GetDataSize())` 将约 4GB 的音频数据写入该微型缓冲区之后，造成大规模堆溢出。同一溢出值作为 `7+sample.GetSize()` 传入 `WritePES`，使其 `data_size` 参数同步错误。
- **触发条件**: 攻击者构造 MP4 文件，令 stsz/trun box 中的某个音频样本大小字段为 0xFFFFFFF9–0xFFFFFFFF（使 `7+size` 绕回至 0–6），同时在对应文件偏移处实际存储约 4 GB 的字节数据（以使 `ReadData` 成功读取）。需要约 4 GB 大小的恶意 MP4 文件。
- **安全影响**: 大规模堆越界写（最多约 4 GB）覆盖相邻堆元数据及对象，最坏情况下可实现任意代码执行（RCE）；必然导致进程崩溃（DoS）。

## VULN: Unsigned Integer Underflow in WritePMT Stuffing Calculation Leading to OOB Read
- **漏洞类别**: memory-safety
- **函数**: AP4_Mpeg2TsWriter::WritePMT()
- **行号**: 860-863
- **CWE**: CWE-191 (Integer Underflow) → CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42hls -e sample-aes input.mp4 output/ → WritePAT/WritePMT → MakeSampleAesAudioDescriptor(descriptor, audio_track->GetSampleDescription(0), ...) 中读取 `esds` box 内 DecoderSpecificInfo（DSI）字节 → `descriptor.SetDataSize(6 + 6 + dsi.GetDataSize())` [Mp42Hls.cpp:795] → `audio_stream->SetDescriptor(descriptor.GetData(), descriptor.GetDataSize())` [Mp42Hls.cpp:1183] → `ts_writer->WritePMT(output)` → line 863: `output.Write(StuffingBytes, AP4_MPEG2TS_PACKET_PAYLOAD_SIZE-(section_length+4))`
- **描述**: 在 `WritePMT`（Ap4Mpeg2Ts.cpp 第 810–819 行）中，`section_length` 被无界累加：`section_length += 5 + m_Audio->m_Descriptor.GetDataSize()`。若描述符大小来自文件（通过 `Mp42Hls.cpp` 的 `MakeSampleAesAudioDescriptor` 读入 `esds` box 的 DSI），当 `section_length + 4 > 184`（即描述符 > ~171 字节，对应 DSI > ~159 字节）时，第 863 行 `AP4_MPEG2TS_PACKET_PAYLOAD_SIZE - (section_length + 4)` 发生无符号下溢（两者均为 `unsigned int`），产生约 `0xFFFFFFCE` 的巨大值，导致 `output.Write(StuffingBytes, ~4GB)` 从仅 188 字节的静态数组 `StuffingBytes` 起始地址连续读取约 4 GB 内存；越界读取其后的只读数据段或触发段错误。
- **触发条件**: 攻击者构造 MP4 文件，在 `esds` box 的 DecoderSpecificInfo 中填充 > 159 字节的任意数据（ESDescriptor 格式允许 DSI 长度为可扩展的 28 位字段，无上界限制）；受害者以 `-e sample-aes` 参数运行 `mp42hls` 处理该文件。
- **安全影响**: 从 `.rodata` 段越界读取的数据写入输出 `.ts` 文件（信息泄露，可能暴露地址布局）；更可能的结果是触及不可读页面导致 SIGSEGV（DoS/崩溃）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
