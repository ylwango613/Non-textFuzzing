I now have complete context. Here is my analysis summary before the final report:

**Key finding:** `avpriv_adts_header_parse` (adts_parser.c:56) validates `size >= AV_AAC_ADTS_HEADER_SIZE` (7 bytes), then at line 66 passes `buf` **directly** to `ff_adts_header_parse_buf`. But `ff_adts_header_parse_buf`'s documented parameter type is `const uint8_t buf[AV_AAC_ADTS_HEADER_SIZE + AV_INPUT_BUFFER_PADDING_SIZE]` (71 bytes), and internally calls `init_get_bits8(&gb, buf, AV_AAC_ADTS_HEADER_SIZE)`. The `init_get_bits` comment in `get_bits.h:511-513` explicitly says: *"buffer must be AV_INPUT_BUFFER_PADDING_SIZE bytes larger than the actual read bits because some optimized bitstream readers read 32 or 64 bit at once and could read over the end."*

By contrast, `av_adts_header_parse` (lines 33-38) correctly allocates `tmpbuf[AV_AAC_ADTS_HEADER_SIZE + AV_INPUT_BUFFER_PADDING_SIZE]` (71 bytes) before calling `ff_adts_header_parse_buf`.

The real call path is `hls_sample_encryption.c:289` → `avpriv_adts_header_parse` → `ff_adts_header_parse_buf(buf, …)` where `buf` may have as few as 7 valid bytes, triggering an OOB read of up to ~8 bytes beyond the buffer.

---

## VULN: avpriv_adts_header_parse passes undersized buffer missing AV_INPUT_BUFFER_PADDING_SIZE to GetBitContext — OOB read
- **漏洞类别**: memory-safety
- **函数**: avpriv_adts_header_parse()
- **行号**: 56-66
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 5.3 (AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:L)
- **严重程度**: Medium
- **攻击向量**: crafted ADTS/HLS media file
- **外部触发路径**: ffmpeg -i <crafted_hls_file> -f null - → avformat_open_input() → ff_hls_read_header() → hls_sample_encryption.c:289 avpriv_adts_header_parse(&adts_hdr, frame->data, ctx->buf_end - frame->data) → adts_parser.c:66 ff_adts_header_parse_buf(buf, *phdr) → adts_header.c:80 init_get_bits8(&gb, buf, AV_AAC_ADTS_HEADER_SIZE) → OOB read in optimized bit reader
- **描述**: `avpriv_adts_header_parse`（adts_parser.c:56）仅检查 `size >= AV_AAC_ADTS_HEADER_SIZE`（7字节），即可通过参数校验，随后在第66行将调用者提供的 `buf` 指针直接传给 `ff_adts_header_parse_buf`。然而 `ff_adts_header_parse_buf` 的函数签名（adts_header.h:63）明确声明其参数类型为 `const uint8_t buf[AV_AAC_ADTS_HEADER_SIZE + AV_INPUT_BUFFER_PADDING_SIZE]`（71字节），内部调用 `init_get_bits8(&gb, buf, AV_AAC_ADTS_HEADER_SIZE)` 初始化 `GetBitContext`。`get_bits.h:511-513` 注释明确指出："buffer must be AV_INPUT_BUFFER_PADDING_SIZE bytes larger than the actual read bits because some optimized bitstream readers read 32 or 64 bit at once and could read over the end"。由于仅保证7字节有效区域，优化后的位读取器（32位或64位字对齐读取）将在7字节边界之外进行越界读取，最多读取8字节超出范围的堆/栈内存。对比而言，`av_adts_header_parse`（adts_parser.c:33-38）通过先分配 `tmpbuf[AV_AAC_ADTS_HEADER_SIZE + AV_INPUT_BUFFER_PADDING_SIZE]`（71字节）再拷贝7字节的方式正确处理了此问题，`avpriv_adts_header_parse` 缺少该中间缓冲区是此漏洞的根因。
- **触发条件**: 攻击者构造一个 HLS 加密流媒体文件，使 ADTS 帧头数据恰好位于内部缓冲区 `ctx->buf_ptr` 所对应内存的末尾（紧邻该内存区块边界），令传入 `avpriv_adts_header_parse` 的 `size` 参数恰好等于7（满足最小检查），随后 `ff_adts_header_parse_buf` 内的 `GetBitContext` 优化读取器将读取边界后的额外字节，导致越界读。
- **安全影响**: 越界读取最多约8字节的进程堆内存（或相邻数据），可导致：(1) 信息泄露——泄露相邻堆块中的指针或敏感数据，辅助绕过 ASLR；(2) 可用性影响——若越界地址跨越页面边界（page boundary），触发 SIGSEGV 进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
