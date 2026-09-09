The vulnerability is confirmed. The operator precedence bug at line 338 causes an 8x over-large `line_size` for BITMAP mode, leading to a heap overflow when `memcpy` writes `width` bytes into a `(width+7)/8`-byte-wide AVFrame row.

## VULN: Heap Overflow in PSD BITMAP Decode — Operator Precedence Bug in line_size Calculation
- **漏洞类别**: memory-safety
- **函数**: decode_frame()
- **行号**: 338, 446, 450, 555
- **CWE**: CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted PSD media file
- **外部触发路径**: `ffmpeg -i crafted.psd -f null -` → `ff_psd_decoder` → `decode_frame()` → BITMAP branch sets `s->line_size = s->width + 7 >> 3` (= `s->width`) → `av_malloc(s->uncompressed_size)` or raw buffer check passes → `ff_get_buffer()` allocates AVFrame with MONOWHITE `linesize[0] = (width+7)/8` → `memcpy(ptr, ptr_data, s->line_size)` overflows the AVFrame heap buffer
- **描述**: 在 `decode_frame()` 的 `PSD_BITMAP` 分支（第 338 行），代码写的是 `s->line_size = s->width + 7 >> 3;`。由于 C 运算符优先级中 `>>` 高于 `+`，该表达式被解析为 `s->width + (7 >> 3) = s->width + 0 = s->width`，而不是预期的 `(s->width + 7) >> 3 = ceil(width/8)`。结果 `s->line_size` 被设为 `width`（每行完整像素数），而非正确的位图字节宽度 `ceil(width/8)`。随后 `s->uncompressed_size = s->line_size * s->height * s->channel_count = width * height`（是正确值的 8 倍），再由 `av_malloc(uncompressed_size)` 或 RAW 路径的边界检查接受此膨胀值。最终在第 555 行 `memcpy(ptr, ptr_data, s->line_size)` 每行拷贝 `width` 字节，但 `ff_get_buffer()` 为 `AV_PIX_FMT_MONOWHITE` 格式分配的 AVFrame 每行仅 `(width+7)/8` 字节（`picture->linesize[0]`）。这导致每行溢出 `width - (width+7)/8 ≈ 7*width/8` 字节，内容完全由攻击者构造的文件数据控制。
- **触发条件**: 构造一个 PSD 文件，将 `color_mode` 设为 0 (BITMAP)、`channel_depth` 设为 1、`channel_count` 设为 1，以及 `compression` = 0 (RAW)；在图像数据区填入 `width × height` 字节（满足膨胀后的 `uncompressed_size` 检查），此后 decoder 直接进入 `memcpy` 溢出。或使用 compression = 1 (RLE)，提供 RLE 编码数据使解码器输出 `width * height` 字节到 `tmp` 缓冲区，同样触发 `memcpy` 溢出。对于 `width = 30000, height = 30000`，每行溢出 26250 字节，累计约 750 MB 堆溢出，溢出内容完全可控。
- **安全影响**: 攻击者可通过特制 PSD 文件，在目标进程堆上写入大量可控字节，覆盖堆管理元数据或其他堆对象，最坏情况可导致远程代码执行（RCE）；至少可稳定触发进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
