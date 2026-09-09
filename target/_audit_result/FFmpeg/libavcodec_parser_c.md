Now I have enough context to write the final audit report. Let me confirm the key points of my analysis:

1. `ff_combine_frame` at line 233 sets `pc->last_index = pc->index`, and at line 256 sets `pc->overread_index = pc->index + next`
2. When `|next| > pc->index`, both `pc->last_index + next` (line 284) and `pc->overread_index` (line 256) become negative
3. The loop at line 283-285 reads `pc->buffer[pc->last_index + next]` with negative indices → heap OOB read
4. The loop at lines 223-224 reads `pc->buffer[pc->overread_index]` with negative `pc->overread_index` → heap OOB read in the next call
5. Parsers returning `i - N` with small `i` (HEVC: `i - 6`, JPEG2000: `i - 11`) are triggerable via crafted media files
6. No validation exists for `|next| ≤ pc->index`

## VULN: Heap OOB Read in ff_combine_frame via Negative Overread Index
- **漏洞类别**: memory-safety
- **函数**: ff_combine_frame()
- **行号**: 223-224, 255-256, 283-285
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 6.1 (AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:L)
- **严重程度**: Medium
- **攻击向量**: crafted media file (HEVC/H.265 or JPEG2000 bitstream)
- **外部触发路径**: ffmpeg -i crafted.mkv/jp2 -f null - -> av_parser_parse2() -> ffcodecparser()->parse() [hevc_parse / jpeg2000_parse] -> hevc_find_frame_end()/find_frame_end() returns `i - 6` (or `i - 11`) -> ff_combine_frame(pc, next=-6, ...) -> heap OOB reads at parser.c:284 (current call) and parser.c:224 (next call)
- **描述**: `ff_combine_frame()` 接收来自各解析器的 `next` 参数（含帧起始偏移量），该值可为负数（表示下一帧起始位于当前累积缓冲区之前若干字节）。代码在第 233 行执行 `pc->last_index = pc->index`，第 255–256 行执行 `pc->overread_index = pc->index + next`，但未校验 `|next| ≤ pc->index`。当 `|next| > pc->index` 时，两处发生越界读：①第 283–285 行的循环访问 `pc->buffer[pc->last_index + next]`（负下标），读取堆缓冲区之前的 malloc 元数据（chunk header）；②下次调用第 223–224 行的 overread 复制循环读取 `pc->buffer[pc->overread_index]`（负下标），将 malloc chunk header 字节复制至 `pc->buffer[0..]`，并作为视频帧数据传递给解码器。HEVC 解析器（`hevc_find_frame_end`，hevc/parser.c:286-299）最多返回 `i - 6`，当 `pc->index < 6` 时即可触发；JPEG2000 解析器（`find_frame_end`，jpeg2000_parser.c:137）最多返回 `i - 11`，当 `pc->index < 11` 时即可触发。两处均无越界保护，`av_assert0(next >= 0 || pc->buffer)` 仅检查 NULL 指针，不阻止负索引访问。
- **触发条件**: 构造一个包含 HEVC（H.265）或 JPEG2000 视频流的畸形 MKV/MP4/JP2 文件，使得：①第一个包/分片仅含数量极少（HEVC ≤ 5 字节，JPEG2000 ≤ 10 字节）的累积数据（END_NOT_FOUND），令 `pc->index` 极小；②后续包的第一个字节恰好在 `i=0` 处触发帧检测，迫使解析器返回 `next = i - 6`（HEVC）或 `next = i - 11`（JPEG2000），使 `pc->last_index + next < 0`。对于 HEVC：当前帧末尾以 `0x00 0x00 0x01` 结束（填充到 `pc->state64`），下一字节是触发帧结束的 NAL 类型字节，`pc->frame_start_found = 1`，返回 `0 - 6 = -6`。
- **安全影响**: 读取 `pc->buffer` 之前的 glibc malloc chunk header 字节（包含堆块大小字段、可能的 tcache/freelist 指针），并将其写入下一帧的起始数据区（`pc->buffer[0..]`）：①在服务器端转码场景（如 FFmpeg API 处理不受信任输入并输出编码流）中，泄漏的堆元数据被编码进输出流，可供攻击者提取，绕过 ASLR；②被污染的帧数据传入硬件加速解码器或特定软件解码器，可能触发下游内存安全问题（DoS 或进一步利用链）；③在 ASAN/Valgrind 环境下必然被检测为 heap-buffer-underflow。

<!-- AUDIT_PROMPT_VERSION: 1 -->
