Based on my thorough analysis, I can now confirm the two key findings and their exact locations. The most important one is at line 319 in `sub2video_copy_rect` (signed-integer overflow bypassing bounds check → OOB write), and a secondary one at lines 1315 and 2376 (missing `sd->size` check before `memcpy` — note that `ffprobe.c` explicitly guards `sd->size >= 9*4` at lines 1102 and 1445, confirming awareness of this path, but `ffmpeg_filter.c` has no such guard).

## VULN: Integer Overflow in sub2video_copy_rect Bounds Check Leading to Heap OOB Write
- **漏洞类别**: memory-safety
- **函数**: sub2video_copy_rect()
- **行号**: 308-336
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-787 (Out-of-Bounds Write)
- **CVSS v3.1**: 7.0 (AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted media file with bitmap subtitle stream
- **外部触发路径**: ffmpeg -i <crafted_mkv_with_bitmap_sub> -vf "subtitles=..." -f null - → filter_thread() → sub2video_frame() [ffmpeg_filter.c:3506] → sub2video_update() [ffmpeg_filter.c:388] → sub2video_copy_rect() [ffmpeg_filter.c:319]
- **描述**: 在 `sub2video_copy_rect` 函数中，对字幕矩形的边界检查 `r->x + r->w > w`（line 319）和 `r->y + r->h > h` 使用有符号 int 加法，未做溢出防护。若字幕解码器产生 `r->x`（或 `r->y`）接近 `INT_MAX` 的值（如 `r->x = 2147483642`，`r->w = 10`），则 `r->x + r->w` 溢出为负数（`-2147483644`），小于画布宽度 `w`，边界检查被绕过。随后 line 326 的 `dst += r->y * dst_linesize + r->x * 4` 中 `r->x * 4` 同样溢出（`2147483642 × 4 = 8589934568`，截断为 int32 = `-24`），使目标指针向堆前方偏移，从而在 lines 329-336 的像素写入循环中发生堆缓冲区越界写。字幕矩形的 `x, y, w, h` 字段由 `ffmpeg_dec.c` 原样从字幕解码器输出中复制（无边界夹断），使得攻击者可通过精心构造的字幕流控制这些值。
- **触发条件**: 构造包含 Bitmap 类型字幕轨道（`SUBTITLE_BITMAP`）的媒体文件（如 MKV/MP4），其中字幕矩形的 `x` 坐标或 `y` 坐标值接近 `INT_MAX/2`（例如 `≥ INT_MAX - width_of_canvas`），同时 `r->data[0]` 指向有效位图数据（即 `r->w * r->h` 尺寸较小可正常分配）。使用 `-vf subtitles=...` 或 `sub2video` 模式触发字幕到视频帧的合成路径。
- **安全影响**: 堆越界写，可覆盖目标指针之前的堆内存（最大可达 `r->w * 4` 字节范围的任意堆块），在最坏情况下可配合 heap spray 实现任意代码执行（RCE）；在无利用的情况下导致进程崩溃（DoS）。

## VULN: Missing sd->size Validation Before memcpy from AV_FRAME_DATA_DISPLAYMATRIX Side Data
- **漏洞类别**: memory-safety
- **函数**: ifilter_parameters_from_frame() / fg_create()
- **行号**: 2374-2378 (ifilter_parameters_from_frame), 1312-1315 (fg_create)
- **CWE**: CWE-125 (Out-of-Bounds Read)
- **CVSS v3.1**: 5.5 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N)
- **严重程度**: Medium
- **攻击向量**: crafted media file
- **外部触发路径**: ffmpeg -i <crafted_file> -f null - → avformat_open_input() → demuxer → avcodec_receive_frame() → ifilter_parameters_from_frame() [ffmpeg_filter.c:2374-2378]
- **描述**: 在 `ifilter_parameters_from_frame()` 的 line 2376 和 `fg_create()` 的 line 1315，代码从帧的 `AV_FRAME_DATA_DISPLAYMATRIX` side data 中 `memcpy` 36 字节到 `ifp->displaymatrix`（`int32_t[9]`），但均未检查 `sd->size >= sizeof(ifp->displaymatrix)`（即 36 字节）。对比：`ffprobe.c` 的 line 1102 和 line 1445 均有显式的 `sd->size >= 9*4` 防御性检查，说明 FFmpeg 开发者已知该路径存在 size 不足的可能，但 `ffmpeg_filter.c` 中的两处调用点均缺少此校验。若 demuxer 或中间处理环节创建了 size < 36 字节的 `AV_FRAME_DATA_DISPLAYMATRIX` side data（例如通过 bitstream filter 或某些格式特定路径），则 `memcpy` 将从 `sd->data` 读取超出分配范围的堆内存，导致堆越界读。
- **触发条件**: 构造一个媒体文件，使其通过 demuxer 或 bitstream filter 生成 `AV_FRAME_DATA_DISPLAYMATRIX` 类型、但 `sd->size < 36` 的帧 side data。任何能够产生 display matrix side data 且未严格限制 size 为 36 字节的 demuxer/decoder/filter 均可触发此读取。
- **安全影响**: 堆越界读，可泄露 `sd->data` 分配块之后的堆内存内容（信息泄露），在某些条件下可导致进程崩溃（DoS）。与 info-leak 配合可辅助 ASLR 绕过，进而在利用链中提升其他漏洞的可利用性。

<!-- AUDIT_PROMPT_VERSION: 1 -->
