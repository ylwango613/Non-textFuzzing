I now have complete context. Let me trace the exact vulnerability:

- `w = AV_RL16(&buf[0])` and `h = AV_RL16(&buf[2])` are raw 16-bit values from the packet.
- `ff_set_dimensions` calls `av_image_check_size2`, which only rejects `w==0 || h==0` — small dimensions like `w=1, h=1` pass.
- `ff_get_buffer` allocates a frame sized for the actual dimensions (e.g., 1 row of luma).
- The MB loop runs `(h+15)/16` times: for `h=1`, this is 1 iteration.
- `tqi_idct_put` unconditionally calls `ff_ea_idct_put_c` four times for luma, writing 8 rows of 8 bytes each, accessing up to `frame->data[0] + 15*linesize + 8`.
- For a 1-pixel-tall frame, only `linesize * 1` bytes are allocated per luma plane. Writes starting at row 1 onward are OOB.

## VULN: Heap Buffer Overflow in tqi_idct_put Due to Missing Minimum Dimension Check
- **漏洞类别**: memory-safety
- **函数**: tqi_decode_frame() / tqi_idct_put()
- **行号**: 136-165 (frame decode), 92-110 (idct_put OOB write)
- **CWE**: CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted TQI media file
- **外部触发路径**: `ffmpeg -i <crafted.tqi> -f null -` → `avformat_open_input()` → `avformat_find_stream_info()` → `tqi_decode_frame()` → `tqi_idct_put()` → `ff_ea_idct_put_c()` [OOB write]
- **描述**: `tqi_decode_frame` 从数据包头部以 `AV_RL16` 读取 `w`（buf[0..1]）和 `h`（buf[2..3]），并以这两个不可信值调用 `ff_set_dimensions(avctx, w, h)`。`ff_set_dimensions` 内部仅通过 `av_image_check_size2` 拒绝 `w==0 || h==0`，对小尺寸（如 `w=1, h=1`）不做拦截，函数正常返回 0。随后 `ff_get_buffer` 按实际维度（1×1 像素）分配 YUV420P 帧缓冲，亮度平面仅 `linesize[0]×1` 字节。MB 迭代循环 `(h+15)/16` 次（`h=1` 时执行 1 次），在 `tqi_idct_put` 中对 block[0]~block[3] 各调用一次 `ff_ea_idct_put_c(dest, linesize, block[n])`。`ff_ea_idct_put_c` 固定向 `dest + i*linesize`（`i=0..7`）写入 8 个 `uint8_t` 值（即 8 行 × 8 字节），第 4 次调用的基地址为 `frame->data[0] + 8*linesize + 8`，最远访问 `frame->data[0] + 15*linesize + 8`。以 `linesize=32` 为例，最远写偏移为 488 字节，而帧缓冲仅约 96 字节（含 64 字节 padding），造成严重的堆越界写入。
- **触发条件**: 攻击者构造 TQI 格式媒体文件，将帧头前 4 字节设为 `w=1, h=1`（或任何 `h<16` 的值），其余 4 字节为合法帧头，后跟满足最小长度（≥12 字节）的伪造有效载荷；`ffmpeg`/`ffplay` 打开该文件并触发 TQI 解码路径即可触发漏洞。
- **安全影响**: 攻击者可向帧缓冲区后方的堆数据写入 0–255 范围内的可控字节（由 IDCT 系数经 `av_clip_uint8` 截断），可通过堆布局操控覆盖相邻堆对象（如函数指针、AVBuffer 引用计数指针、FreeBSD jemalloc/Linux ptmalloc 元数据），在最坏情况下实现远程代码执行（RCE）；即使利用受限，也可稳定导致进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
