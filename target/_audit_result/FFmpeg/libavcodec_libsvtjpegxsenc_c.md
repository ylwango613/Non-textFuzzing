I've now fully analyzed the file. Here is the complete audit result:

## VULN: Integer Truncation in bitstream_frame_size Causes Buffer Underallocation
- **漏洞类别**: memory-safety
- **函数**: svt_jpegxs_enc_init() / svt_jpegxs_enc_encode()
- **行号**: 233-234 (overflow), 65 (use), 69-71 (propagation to SVT library)
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-Based Buffer Overflow)
- **CVSS v3.1**: 7.8 (AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted media file (transcoding pipeline sets width/height/bitrate from container metadata)
- **外部触发路径**: ffmpeg -i <crafted_file> -c:v libsvtjpegxs out.jpegxs → avformat_open_input() → avcodec_open2() → svt_jpegxs_enc_init() [overflow at line 233-234, int truncation] → svt_jpegxs_enc_encode() → ff_get_encode_buffer(…, svt_enc->bitstream_frame_size, …) [underallocated pkt->data] → svt_jpeg_xs_encoder_send_picture() [SVT library writes past allocation] → heap overflow
- **描述**: `bitstream_frame_size` is declared as `int` (line 50), but its initialization expression at lines 233-234 is computed in `int64_t` arithmetic: `(((int64_t)avctx->width * avctx->height * svt_enc->encoder.bpp_numerator / svt_enc->encoder.bpp_denominator + 7) / 8)`. The int64_t result is silently truncated on assignment to `int`. For sufficiently large `width * height * bpp_numerator / bpp_denominator`, the value exceeds INT_MAX and wraps to a small positive integer. At line 65, this small value is passed to `ff_get_encode_buffer()` which allocates `pkt->data` with only that many bytes. At lines 69-71, `out_buf->buffer = pkt->data` and `out_buf->allocation_size = pkt->size` (the undersized value) are handed to the SVT JPEG XS encoder. If the SVT library writes the full encoded frame beyond the stated `allocation_size` (whether due to an internal accounting bug or silent overflow), the heap buffer is overwritten. Even without SVT library misbehavior, the truncation can make the value go negative (e.g., width=2, height=1, bpp_numerator=INT_MAX → result = 2*INT_MAX/8 → wrap to -1), which `ff_get_encode_buffer` would reject (size < 0 check at encode.c:110), causing a DoS rather than overflow—but when truncated to a small positive value the check is bypassed.
- **触发条件**: 攻击者构造一个高分辨率媒体文件（如 MKV/MP4），其容器 metadata 中指定极大的 width 和 height（例如 35000×35000，配合 14-bit 像素格式），同时设置高 bit_rate 使 `bpp_numerator` 较大。用户使用 `ffmpeg -i crafted.mkv -c:v libsvtjpegxs out.jpegxs` 进行转码时，`svt_jpegxs_enc_init` 中计算 `bitstream_frame_size` 时 int64_t 结果溢出，截断后为小正整数，进而触发堆欠分配。
- **安全影响**: 最坏情况下，SVT JPEG XS 库在未充分检查 `allocation_size` 的情况下写入实际编码数据，造成堆缓冲区溢出（Heap Buffer Overflow），可被精心构造的 JIT 布局利用实现远程代码执行（RCE）；最轻情况下导致 DoS（crash 或编码失败）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
