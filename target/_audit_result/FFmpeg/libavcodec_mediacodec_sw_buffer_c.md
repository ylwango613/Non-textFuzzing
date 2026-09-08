I now have full context. Let me write the final audit report.

## VULN: OOB Read via Unchecked `src` Offset in All YUV420 SW Copy Functions
- **漏洞类别**: memory-safety
- **函数**: ff_mediacodec_sw_buffer_copy_yuv420_planar(), ff_mediacodec_sw_buffer_copy_yuv420_semi_planar(), ff_mediacodec_sw_buffer_copy_yuv420_packed_semi_planar(), ff_mediacodec_sw_buffer_copy_yuv420_packed_semi_planar_64x32Tile2m8ka()
- **行号**: 90-127, 144-176, 195-224, 304-333
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted media file (Android MediaCodec path)
- **外部触发路径**: ffmpeg -i <crafted_video> -f null - → avformat_open_input() → av_read_frame() → avcodec_send_packet() → ff_mediacodec_dec_receive() → mediacodec_wrap_sw_video_buffer() → ff_mediacodec_sw_buffer_copy_yuv420_planar() [or other copy variant] → OOB memcpy(src, ...)
- **描述**: 所有四个 YUV420 拷贝函数都接受 `data`（MediaCodec 输出缓冲区）和 `size`（该缓冲区的实际字节大小）两个参数，但在函数体内 **`size` 参数从未被使用**。每个函数都在 `data + info->offset` 基础上，用来自 Android MediaFormat 的 `s->stride`、`s->slice_height`、`s->crop_top`、`s->crop_left` 等字段累加偏移量，算出 `src` 指针，然后直接调用 `memcpy`，既不校验 `src` 是否仍在 `[data, data+size)` 范围内，也不校验拷贝长度 `height*stride` 是否超出剩余空间。以 `ff_mediacodec_sw_buffer_copy_yuv420_planar` 的 U 平面（i==2）为例：`src += s->slice_height * s->stride; src += ((s->slice_height+1)/2)*stride;`——若 `s->slice_height` 或 `s->stride` 异常大，`src` 可越过 `data+size` 指向任意堆内存，随后 `memcpy(frame->data[i], src, height*stride)` 从越界地址读取数据写入帧缓冲。`s->slice_height` 与 `s->stride` 来自 `AMEDIAFORMAT_GET_INT32(s->slice_height, "slice-height", 0)` 和 `AMEDIAFORMAT_GET_INT32(s->stride, "stride", 0)`，这两个键值由底层解码器依据压缩码流填写，未施加任何上界检查（`mediacodecdec_common.c` 第 576-590 行）。
- **触发条件**: 攻击者构造一个畸形 H.264/HEVC/VP8/VP9 视频文件（mp4/mkv 等容器），使 Android MediaCodec 硬件/软件解码器在输出格式中报告一个大于实际分配缓冲区容量的 `slice-height` 或 `stride` 值（例如 `slice_height = 0x7FFFFFFF`），从而使 `src` 偏移量远超 `data + size`；FFmpeg 在 Android 上解码该文件时即可触发。
- **安全影响**: OOB 堆内存读取，可将 MediaCodec 输出缓冲区之外的相邻堆内存内容写入解码帧，造成敏感内存（如其他帧数据、指针）信息泄露；在极端情况下（`src` 跨越未映射页）导致进程崩溃（DoS）。若结合后续的帧输出路径可进一步利用为信息泄露原语。

## VULN: Signed Integer Overflow in `height * stride` Passed to memcpy → Heap OOB Write
- **漏洞类别**: memory-safety
- **函数**: ff_mediacodec_sw_buffer_copy_yuv420_planar(), ff_mediacodec_sw_buffer_copy_yuv420_semi_planar(), ff_mediacodec_sw_buffer_copy_yuv420_packed_semi_planar()
- **行号**: 111, 159, 207
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted media file (Android MediaCodec path)
- **外部触发路径**: ffmpeg -i <crafted_video> -f null - → avformat_open_input() → avcodec_send_packet() → ff_mediacodec_dec_receive() → mediacodec_wrap_sw_video_buffer() → ff_mediacodec_sw_buffer_copy_yuv420_planar() → memcpy(frame->data[i], src, height * stride) [signed overflow]
- **描述**: 在三个非 QCOM tile 的拷贝函数中，第 111/159/207 行分别执行 `memcpy(frame->data[i], src, height * stride)` 或 `memcpy(frame->data[i], src, height * s->stride)`。其中 `height`（从 `avctx->height` 赋值，`int` 型）和 `stride`/`s->stride`（从 `s->stride` 赋值，`int` 型）均为有符号整数。当两者的乘积超过 `INT_MAX` 时，发生有符号整数溢出（C 语言 UB），结果可能为负值；该负值隐式转换为 `size_t`（`memcpy` 第三参数类型）时，在 64 位平台上变为接近 SIZE_MAX 的极大无符号值（例如 `-2147483648` → `0xFFFFFFFF80000000`），导致 `memcpy` 从 `src`（已越过 MediaCodec 缓冲区边界）读取海量数据，并向 `frame->data[i]`（已分配的帧缓冲区）之外大量写入，造成堆溢出。`s->stride` 的来源同上，由 `AMEDIAFORMAT_GET_INT32(s->stride, "stride", 0)` 读取，无上界限制（`mediacodecdec_common.c` 第 576-577 行）。
- **触发条件**: 攻击者构造一个畸形视频文件，使解码器输出格式中的 `stride` 值达到 `> INT_MAX / avctx->height` 的水平（例如 `height=32768, stride=65536`，乘积 2^31 溢出）；FFmpeg 在 Android 上通过 MediaCodec 路径解码该文件时触发。
- **安全影响**: 任意长度的堆写越界，在目标帧缓冲区之后的堆内存中写入来自 OOB 源地址的数据，最坏情况下可覆盖相邻堆对象（如函数指针、vtable 等），实现远程代码执行（RCE）；同时伴随 OOB 读导致进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
