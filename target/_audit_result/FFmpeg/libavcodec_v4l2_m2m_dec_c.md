I have now fully analyzed `v4l2_m2m_dec.c` (269 lines) and traced its complete call chain through `v4l2_context.c`, `v4l2_buffers.c`, `v4l2_m2m.c`, and the associated headers.

**Analysis summary:**

**Architecture**: This file is a hardware decoder wrapper. All actual encoded bitstream processing (H.264, HEVC, VP8, VP9, etc.) is delegated to a Linux kernel V4L2 driver via ioctl(). FFmpeg's userspace role is limited to: (1) initializing the kernel context, (2) enqueuing encoded packets, (3) dequeuing decoded frames.

**Examined potential issues:**

1. **`buf.index` missing bounds check** (`v4l2_context.c:412`): `avbuf = &ctx->buffers[buf.index]` uses the kernel-returned VIDIOC_DQBUF index without validating `buf.index < ctx->num_buffers`. However, `buf.index` is managed entirely by the kernel's buffer pool — it is NOT derived from the media file's content, and a legitimate kernel driver always returns valid indices. Not triggerable by crafted media file.

2. **Integer overflow in `v4l2_get_framesize_compressed()`** (`v4l2_context.c:119`): `(width * height * 3 / 2) / 2 + 128` can overflow for large attacker-controlled `coded_width`/`coded_height`, yielding a wrong `sizeimage` hint to the kernel. However, actual buffer sizes are re-read from the kernel via VIDIOC_QUERYBUF — the kernel does not use this value to size the userspace allocation. No userspace memory corruption.

3. **`v4l2_buffer_buf_to_swframe` NV12/YUV420P pointer arithmetic**: `frame->data[1] = frame->buf[0]->data + bytesperline * height` — assumes mmap'd buffer is large enough. Both values come from the kernel (VIDIOC_G_FMT and VIDIOC_QUERYBUF), which is trusted in this model.

4. **`avbuf->num_planes` loop bounds**: Bounded by `VIDEO_MAX_PLANES = 8 = AV_NUM_DATA_POINTERS`, safe.

5. **`v4l2_bufref_to_buf` offset underflow**: Only reachable via encoder path (`v4l2_m2m_enc.c`), not decoder.

**Verdict**: This hardware decoder wrapper does not contain memory-safety vulnerabilities that are independently triggerable by a crafted media file. The kernel driver is the trusted processing boundary; attacker-controlled data from the media file never reaches FFmpeg userspace in a form that causes memory corruption.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
