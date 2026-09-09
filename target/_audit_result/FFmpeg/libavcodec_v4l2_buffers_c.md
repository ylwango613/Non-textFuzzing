I now have full context. Let me trace the mixed-type arithmetic path in the two key bugs carefully before writing the report.

**Analysis Group 1 — `v4l2_bufref_to_buf` (lines 299–319)**

```c
unsigned int bytesused, length;
length = out->plane_info[plane].length;    // size_t → unsigned int
bytesused = FFMIN(size+offset, length);    // int+int overflow possible
memcpy(mm_addr+offset, data, FFMIN(size, length-offset)); // ← key line
```

`FFMIN(a,b)` = `(a) > (b) ? (b) : (a)` (macros.h:49). When `offset > length` (both treated as unsigned in the subtraction): `length - offset` wraps to ~4 GB. Then the comparison `(uint)size > ~4GB` is false, so FFMIN returns the wrapped ~4 GB as the memcpy count. Additionally, `mm_addr + offset` is already past the mmap region. Both combine to crash/corruption.

In `v4l2_buffer_swframe_to_buf` (lines 397–416): if `frame->linesize[0]` is stride-padded (e.g., 4096 for a 1920-wide frame), plane-0 size = 4096 × 1080 = 4,423,680 while the mmap buffer was negotiated for 1920 × 1080 × 3/2 = 3,110,400. After the plane-0 call, `offset += 4,423,680`. When plane-1 call arrives: `offset = 4,423,680 > length = 3,110,400` → underflow + OOB write past mmap.

**Analysis Group 2 — `v4l2_buf_to_bufref` (lines 279–297)**

```c
*buf = av_buffer_create(
    (char *)in->plane_info[plane].mm_addr + in->planes[plane].data_offset,
    in->plane_info[plane].length,   // ← BUG: should be length - data_offset
    v4l2_free_buffer, in, 0);
```

`data_offset` is filled by VIDIOC_DQBUF from the kernel driver (comment on line 286 confirms it is non-zero for VP8). The buffer data pointer starts at `mm_addr + data_offset`, but the reported size is `length` (the full mmap size), not `length − data_offset`. Any downstream code (decoder, codec parser) that reads up to `buf->size` bytes from `buf->data` will read `data_offset` bytes past the end of the mmap region → OOB read → potential info-leak or crash.

## VULN: v4l2_bufref_to_buf unsigned-underflow in length-offset → OOB write past mmap
- **漏洞类别**: memory-safety
- **函数**: v4l2_bufref_to_buf()
- **行号**: 306-309
- **CWE**: CWE-191 (Integer Underflow) → CWE-787 (Out-of-bounds Write)
- **CVSS v3.1**: 7.8 (AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted media file (via V4L2 M2M transcoding pipeline)
- **外部触发路径**: ffmpeg -i crafted.mp4 -c:v v4l2m2m out.mkv → avcodec_send_packet() → ff_v4l2_context_enqueue_packet() → ff_v4l2_buffer_avframe_to_buf() → v4l2_buffer_swframe_to_buf() → v4l2_bufref_to_buf() [OOB write]
- **描述**: 在 `v4l2_bufref_to_buf`（v4l2_buffers.c:306–309）中，局部变量 `length`（`unsigned int`，从 `plane_info[plane].length` 截取）与参数 `offset`（`int`）进行无符号减法 `length-offset`。当 `v4l2_buffer_swframe_to_buf` 中的非平面路径（lines 397–416）累计各平面字节数时，若输入帧的 `linesize` 含对齐填充（stride padding），第 0 平面写入后 `offset += padded_luma_size` 可超出 mmap 缓冲区总长度 `length`。下次调用时 `offset > length`，`length - offset` 发生无符号整数下溢，产生接近 2³²−1 的巨大值；`FFMIN(size, ~4GB)` 通过混合有符号/无符号比较返回 ~4GB 作为 `memcpy` 的 `count`；同时写目标 `mm_addr + offset` 已指向 mmap 区域之外，导致越界写或巨型拷贝引发内存破坏。
- **触发条件**: 攻击者构造一个视频文件（如 MP4/MKV），使软件解码器输出帧的 `linesize[0]` 含对齐填充（例如 4096 字节/行）而 V4L2 硬件编码器按无填充格式协商缓冲区（例如 1920 字节/行 × 1080 行）。使用 `ffmpeg -i crafted.mp4 -c:v v4l2m2m out.mkv` 转码时，两者的字节步长不一致即可触发：`padded_luma_size = linesize[0] * height > driver_mmap_length`，第 0 平面拷贝之后 `offset` 超界，第 1 平面拷贝时发生下溢。
- **安全影响**: 最坏情况下可写入 mmap 映射区域之后的相邻内存（堆缓冲区或其他内存映射），导致进程崩溃（DoS）或潜在的堆布局控制后远程代码执行（RCE）；在多租户媒体处理服务中尤为危险。

## VULN: v4l2_buf_to_bufref overstates AVBufferRef size by data_offset → OOB read
- **漏洞类别**: memory-safety
- **函数**: v4l2_buf_to_bufref()
- **行号**: 287-288
- **CWE**: CWE-131 (Incorrect Calculation of Buffer Size) → CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 6.1 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:L)
- **严重程度**: Medium
- **攻击向量**: crafted media file (via V4L2 M2M decode → encoded packet output path)
- **外部触发路径**: ffmpeg -i crafted.mp4 -c:v v4l2m2m out.mkv → avcodec_receive_packet() → ff_v4l2_context_dequeue_packet() → ff_v4l2_buffer_buf_to_avpkt() → v4l2_buf_to_bufref() → downstream codec parser reads pkt->buf past mmap end
- **描述**: 在 `v4l2_buf_to_bufref`（v4l2_buffers.c:287–288）中，`av_buffer_create` 的 `data` 参数正确偏移了 `planes[plane].data_offset`（起始于 `mm_addr + data_offset`），但 `size` 参数错误地传入了全量 mmap 大小 `plane_info[plane].length`，而非剩余可用字节数 `length - data_offset`。代码注释（第 286 行）明确指出 `data_offset` 对 VP8 编码是非零的。由此，`AVBufferRef` 多声明了 `data_offset` 个字节，使 `buf->size` 超出实际 mmap 区域末端。当下游解码器或码流解析器依据 `buf->size` 边界读取数据时（如 `pkt->size = bytesused = length` 时），将越过 `mm_addr + length` 读取内核/进程内存之外的数据，导致越界读。
- **触发条件**: 攻击者构造一段使用 VP8 或其他要求非零 `data_offset` 的编码格式的视频文件，在配备支持 V4L2 M2M 硬件编码器的设备上通过 FFmpeg 转码。若 V4L2 驱动返回 `data_offset > 0` 且 `bytesused = length`，则任何读取完整 `pkt->data[0..pkt->size-1]` 的下游码流解析器即可触发 `data_offset` 字节的越界读。
- **安全影响**: 越界读取 mmap 区域之后的内核/进程内存，可能导致敏感信息泄露（信息披露）或因访问非法页面而崩溃（DoS）；在媒体转码服务中可被利用进行内存探测。

<!-- AUDIT_PROMPT_VERSION: 1 -->
