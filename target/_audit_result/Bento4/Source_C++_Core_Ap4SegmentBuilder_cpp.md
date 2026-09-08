I now have a thorough understanding of the file. Let me compile the final report based on all findings.

**Group 1 findings (lines 1–270):**
- `mdat_size` (AP4_UI32) accumulates sample sizes without overflow check (lines 157–171) — wrong box-header value written to stream, not a memory corruption in-process → logic bug only, excluded.
- `sample_data_size` (unsigned int) accumulates NAL sizes without overflow check (lines 230–232) → undersized MemoryByteStream; AP4_MemoryByteStream::WritePartial can grow dynamically, BUT the `space_needed = m_Position + bytes_to_write` computation inside WritePartial can itself overflow at the second huge write, bypassing the Reserve/SetDataSize path and passing an out-of-bounds write to AP4_CopyMemory. Requires ~2GB NAL units — extremely impractical.

**Group 2 findings (lines 490–555):**
- Line 526: `AP4_DataBuffer sample_data(frame.m_Info.m_FrameLength)` uses an unvalidated value from the ADTS parser without any bounds check. The ADTS parser's `FindFrame()` subtracts `AP4_ADTS_HEADER_SIZE (7)` from the 13-bit `m_FrameLength` field without first checking `m_FrameLength >= 7`. If the crafted ADTS frame encodes `frame_length = 0–6`, the subtraction wraps to `0xFFFFFFF9–0xFFFFFFFF`. FindFrame returns `AP4_SUCCESS` with this huge value. The SegmentBuilder then tries to allocate ~4GB → bad_alloc crash (DoS), or, on overcommit Linux, allocates virtual memory and passes the huge count to `ReadBytes()`, which in turn reads 4GB past the 8192-byte ring buffer. This is a realistic, small-file trigger (7-byte crafted ADTS header is sufficient).

## VULN: AP4_AacSegmentBuilder::Feed Uncontrolled Memory Allocation via ADTS Frame Length Underflow
- **漏洞类别**: memory-safety
- **函数**: AP4_AacSegmentBuilder::Feed()
- **行号**: 526-528
- **CWE**: CWE-191 (Integer Underflow) → CWE-789 (Uncontrolled Memory Allocation) / CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 6.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted ADTS/AAC file
- **外部触发路径**: 攻击者提供精心构造的 ADTS 文件（≥7 字节，frame_length 字段=0–6）→ FragmentCreatorTest/任何调用 AP4_AacSegmentBuilder::Feed() 的工具 → AP4_AacSegmentBuilder::Feed() 调用 m_FrameParser.FindFrame(frame) → AP4_AdtsParser::FindFrame() 解析头部，在未校验 adts_header.m_FrameLength >= AP4_ADTS_HEADER_SIZE(7) 的情况下计算 frame.m_Info.m_FrameLength = adts_header.m_FrameLength(0) − 7 = 0xFFFFFFF9（无符号下溢），随后以 peek 到同一头部的方式绕过下一帧校验，返回 AP4_SUCCESS → Ap4SegmentBuilder.cpp:526 AP4_DataBuffer sample_data(0xFFFFFFF9) → new AP4_Byte[0xFFFFFFF9]（~4 GB 分配）→ 在大多数系统上抛出 bad_alloc 导致进程崩溃；在启用内存 overcommit 的 Linux 系统上分配成功后，Ap4SegmentBuilder.cpp:528 frame.m_Source->ReadBytes(ptr, 0xFFFFFFF9) 在 AP4_BitStream 的 8192 字节环形缓冲区上发生越界读取约 4 GB
- **描述**: `AP4_AacSegmentBuilder::Feed()` 调用 ADTS 解析器 `FindFrame()` 后，直接将返回的 `frame.m_Info.m_FrameLength` 用于堆内存分配（第 526 行 `AP4_DataBuffer sample_data(frame.m_Info.m_FrameLength)`）和随后的 `ReadBytes`（第 528 行），未对该值进行任何上界或合理性校验。ADTS 解析器在 `FindFrame()` 的 272 行计算 `frame.m_Info.m_FrameLength = adts_header.m_FrameLength − AP4_ADTS_HEADER_SIZE(7)` 时，未事先验证 `adts_header.m_FrameLength >= 7`，导致当 13 位 `frame_length` 字段为 0–6 时发生无符号整数下溢，产生最大约 4 GB 的分配请求值。进一步地，`FindFrame()` 在 peek 下一帧头部时（frame_length=0 时跳过 0 字节后）会读到当前帧的相同字节，使合法性校验和 `MatchFixed` 均通过，从而返回 `AP4_SUCCESS`，使下溢值无感知地传递到 SegmentBuilder。
- **触发条件**: 构造一个 7 字节 ADTS 帧，其中 bits[30:18]（aac_frame_length 字段）编码为 0（或 1–6），且 sampling_frequency_index < 13、layer = 00，使 `AP4_AdtsHeader::Check()` 通过。将该文件作为输入传递给使用 AP4_AacSegmentBuilder 的工具（如 FragmentCreatorTest 的 audio 模式）。
- **安全影响**: 在绝大多数系统上，bad_alloc 异常导致进程立即崩溃（拒绝服务）。在启用内存过度提交（vm.overcommit_memory=1）的 Linux 系统上，约 4 GB 的分配可能成功，随后 `ReadBytes()` 将对 AP4_BitStream 的 8192 字节堆缓冲区进行约 4 GB 的越界堆读取，可能导致相邻堆数据泄露（信息泄露），在特殊内存布局下存在进一步利用的理论可能。

<!-- AUDIT_PROMPT_VERSION: 1 -->
