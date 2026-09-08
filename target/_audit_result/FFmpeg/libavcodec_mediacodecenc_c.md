Now I have a complete picture of the code. Let me summarize findings from all sections:

**Batch 1 (lines 1-600)**: `copy_frame_to_buffer` (lines 221-247) sets dst pointer offsets based on `s->width * s->height` (int arithmetic) but the `size` parameter is never used for bound validation.

**Batch 2 (lines 600-1200)**: Two concrete bugs:
- Lines 826-827: `input_buf` from `ff_AMediaCodec_getInputBuffer` is used immediately in `copy_frame_to_buffer` without a NULL check. From `mediacodec_wrapper.c:1710`, `GetDirectBufferAddress` can return NULL on JNI failure.
- Lines 723, 738: `memcpy` from `out_buf + out_info.offset` for `out_info.size` bytes without validating `out_info.offset + out_info.size <= out_size`.

## VULN: Null Pointer Dereference in mediacodec_send — Unchecked getInputBuffer Return Value
- **漏洞类别**: memory-safety
- **函数**: mediacodec_send()
- **行号**: 826-827
- **CWE**: CWE-476 (NULL Pointer Dereference)
- **CVSS v3.1**: 5.5 (AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted media file (transcoding scenario)
- **外部触发路径**: ffmpeg -i <crafted_file> -vcodec h264_mediacodec output.mp4 → avcodec_send_frame() → mediacodec_encode() → mediacodec_send() → ff_AMediaCodec_getInputBuffer() returns NULL → copy_frame_to_buffer(avctx, frame, NULL, input_size) → av_image_copy2 writes to NULL-derived addresses
- **描述**: 在 `mediacodec_send`（第826-827行）中，`ff_AMediaCodec_getInputBuffer` 的返回值 `input_buf` 未经 NULL 检查即被直接传入 `copy_frame_to_buffer`。在 JNI 实现（`mediacodec_wrapper.c:1710`）中，`GetDirectBufferAddress` 在传入的 ByteBuffer 为 NULL 或非 direct buffer 时会返回 NULL；NDK 路径下 `AMediaCodec_getInputBuffer` 也可能返回 NULL。`copy_frame_to_buffer` 随即以 `dst = NULL` 计算偏移后调用 `av_image_copy2`，对 `NULL + s->width*s->height` 等地址执行内存写操作，造成空指针解引用写操作（crash）。
- **触发条件**: 攻击者需要提供一个经精心构造的媒体文件，使 FFmpeg 以 `-vcodec h264_mediacodec` 转码（Android 环境），同时设法让 MediaCodec JNI/NDK 的 `getInputBuffer` 调用返回 NULL（例如在特定 Android 设备/API 版本上 ByteBuffer 获取失败）。
- **安全影响**: 进程崩溃（DoS）；在未开启 NULL 页保护的场景下（如可 mmap 地址 0 的嵌入式 Android 系统），写操作偏移指向攻击者可控内存区域，理论上可提升至内存破坏/代码执行。

## VULN: Out-of-Bounds Read in mediacodec_receive — Missing out_info.offset + out_info.size Bounds Check
- **漏洞类别**: memory-safety
- **函数**: mediacodec_receive()
- **行号**: 723, 738
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 4.4 (AV:L/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted media file
- **外部触发路径**: ffmpeg -i <crafted_file> -vcodec h264_mediacodec output.mp4 → mediacodec_encode() → mediacodec_receive() → ff_AMediaCodec_dequeueOutputBuffer()/on_output_available() 返回含异常 offset/size 的 FFAMediaCodecBufferInfo → memcpy(s->extradata, out_buf + out_info.offset, out_info.size) / memcpy(pkt->data + extradata_size, out_buf + out_info.offset, out_info.size)
- **描述**: 第701行通过 `ff_AMediaCodec_getOutputBuffer` 获得 `out_buf`（容量为 `out_size`），但第723行和第738行的 `memcpy` 操作在执行前均未校验 `out_info.offset + out_info.size <= out_size`。若 `out_info.offset` 或 `out_info.size` 异常（如恶意/存在 bug 的 MediaCodec 驱动返回超界值，或 AV1 路径下 line 715 的 `out_info.offset += 4` 加上 `out_info.size` 超出 `out_size`），`memcpy` 的读取源地址 `out_buf + out_info.offset` 加上 `out_info.size` 个字节将越过 MediaCodec 输出缓冲区边界，造成堆上 OOB read，读取内容被复制进 `s->extradata` 或 `pkt->data`，泄露相邻堆内存到输出包。
- **触发条件**: 攻击者提供特制媒体文件触发 AV1 编码路径（line 708-716），或在某些 Android OEM 驱动下诱使 MediaCodec 返回 `offset + size > buffer_size` 的 BufferInfo；AV1 路径下若 `out_info.size == 4`（line 710 检查 `<= 4` 通过后 `size -= 4` 得 0，`offset += 4` 可能越界）存在边界情形值得关注。
- **安全影响**: 堆内存信息泄露（OOB read），输出到编码后的媒体包中；在沙箱环境下可辅助 ASLR 绕过；结合其它写操作漏洞可升级为 RCE。

<!-- AUDIT_PROMPT_VERSION: 1 -->
