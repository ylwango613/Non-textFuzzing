Complete analysis of `libxavs2.c`:

**Key findings:**

1. **`xavs2_copy_frame_with_shift` pointer arithmetic** (line 144): `p_plane` is `uint16_t*` but `p_plane += pic->img.i_stride[plane]` advances by `i_stride * 2` bytes. Cross-referencing `libxavs.c:136` and `libx264.c:501` confirms `i_stride` values are byte-unit strides (set from `frame->linesize[]`). This IS a latent OOB write bug — but **unreachable** in the current configuration: `CODEC_PIXFMTS` only registers `AV_PIX_FMT_YUV420P`, so `bit_depth=8`, `enc_sample_size=1`, `in_sample_size=1`, they are always equal, and `xavs2_copy_frame_with_shift` is dead code.

2. **`xavs2_opt_set2` macro with 16-byte stack buffer**: `av_strlcatf` respects the buffer size — no overflow, only silent value truncation.

3. **`memcpy(pkt->data, cae->packet.stream, cae->packet.len)`** at line 235: safely bounded — the packet buffer is allocated to exactly `cae->packet.len` bytes via `ff_get_encode_buffer` at line 221.

4. **Encoder scope**: This file is a pure encoder wrapper (not a decoder/demuxer). It is only invoked when the user explicitly requests `-c:v libxavs2`, not when parsing a malicious media file via `ffmpeg -i <file> -f null -`.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
