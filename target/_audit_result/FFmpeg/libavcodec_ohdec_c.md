The analysis is complete. I have confirmed:

1. **Send path** (line 594): `OH_AVBuffer_GetCapacity` IS called — capacity validated before `memcpy`.
2. **Receive path** (line 505): `OH_AVBuffer_GetCapacity` is **never called** — no validation before using `stride × slice_height` offsets into the buffer.
3. **No mutex** protects `s->stride`, `s->slice_height`, `s->width`, `s->height`, `s->got_stream_info` in either `oh_decode_on_stream_changed()` (writer, HW-codec callback thread) or `oh_decode_wrap_sw_buffer()` (reader, FFmpeg decode thread).

## VULN: OOB Read via TOCTOU Race on Format Fields in oh_decode_wrap_sw_buffer
- **漏洞类别**: memory-safety
- **函数**: oh_decode_wrap_sw_buffer()
- **行号**: 489-533 (核心读取路径 505-522；数据源 oh_decode_on_stream_changed 219-296)
- **CWE**: CWE-125 (Out-of-bounds Read) / CWE-362 (Race Condition)
- **CVSS v3.1**: 6.3 (AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted H.264 / HEVC media file
- **外部触发路径**: `ffmpeg -i crafted.h264 -f null -` → `avcodec_receive_frame()` → `oh_decode_receive_frame()` → `oh_decode_output_frame()` → `oh_decode_wrap_sw_buffer()` — 并发地由硬件编解码器回调线程调用 `oh_decode_on_stream_changed()` 更新 `s->stride`/`s->slice_height`
- **描述**: `oh_decode_wrap_sw_buffer()` 通过 `OH_AVBuffer_GetAddr(output->buffer)` 获取输出缓冲区指针 `p`，然后以 `s->stride`（来自硬件格式变更通知）作为行宽参数调用 `av_image_fill_linesizes`，再以 `s->slice_height` 调用 `av_image_fill_pointers` 计算 UV 平面偏移量（NV12 格式下 `src[1] = p + stride × slice_height`），最后 `av_image_copy2` 从该地址读取数据。**关键缺陷一（缺少容量校验）**：在接收路径中从未调用 `OH_AVBuffer_GetCapacity(output->buffer)` 来验证缓冲区实际容量是否 ≥ `stride × slice_height × format_factor`，而发送路径（`oh_decode_send_pkt` 第 594 行）则正确调用了该函数。**关键缺陷二（数据竞争）**：`s->stride`、`s->slice_height`、`s->width`、`s->height`、`s->got_stream_info` 在 `oh_decode_on_stream_changed()`（硬件编解码器回调线程）中写入，在 `oh_decode_wrap_sw_buffer()` / `oh_decode_output_frame()`（FFmpeg 解码线程）中读取，双方均未持有任何互斥锁。两者叠加：当视频流发生分辨率变更（旧格式 F1：stride=1920、slice_height=1088；新格式 F2：stride=3840、slice_height=2160），旧格式 F1 的输出缓冲区仍在输出队列中等待处理时，`oh_decode_on_stream_changed` 将 `s->stride`/`s->slice_height` 更新为 F2 的较大值。FFmpeg 解码线程取出 F1 的小缓冲区并以 F2 的 stride/slice_height 计算 `src[1] = p + 3840 × 2160`（约 8 MB），远超 F1 缓冲区实际大小（约 3 MB），导致 `av_image_copy2` 越界读取堆上相邻内存。
- **触发条件**: 构造含有中途分辨率增大的 H.264 或 HEVC 码流（通过新 SPS/VPS 切换分辨率，H.264/HEVC 规范合法支持此特性）。当新格式通知与旧格式输出缓冲区处理交叉时，触发越界读取。ffmpeg 命令行 `-c:v h264_ohcodec`（或 HEVC 变体）即可激活该解码器。
- **安全影响**: 堆越界读取：可能泄露堆上相邻内存内容（敏感数据信息泄露），并可导致进程崩溃（DoS）。在内存布局可预测的场景下，结合其他原语有潜在信息泄露利用价值。

<!-- AUDIT_PROMPT_VERSION: 1 -->
