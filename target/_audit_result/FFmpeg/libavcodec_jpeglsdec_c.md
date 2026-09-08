After exhaustive analysis of `/data/ylwang/non-textfuzz/target/FFmpeg/libavcodec/jpeglsdec.c` and its call chain, including:

1. All array accesses into `JLSState` fields (`A[367]`, `B[367]`, `C[365]`, `N[367]`) — context values are in [0, 364] for regular mode and [365, 366] for run-termination, all within declared array bounds.

2. `ff_log2_run` — the array has 41 elements (indices 0–40); `run_index[comp]` is bounded to ≤ 31 by the `< 31` guard, so `ff_log2_run[31] = 15` is always within bounds. Maximum run size = `1 << 15 = 32768`, and the `x + r*stride > w` check prevents OOB writes into `dst`.

3. `av_mallocz(s->picture_ptr->linesize[0])` for the `zero` buffer — accessed up to index `j + (w - stride)` where `j ≤ 2` and `w = s->width * stride`, giving max index `2 + s->width*3 - 3 = s->width*3 - 1 < linesize[0]` for RGB24.

4. Palette writes in `ff_jpegls_decode_lse` case 2/3 — `k = (uint8_t)(i << shift)` is inherently bounded [0, 255], within the 256-entry `uint32_t pal[]`.

5. `nb_components` validation in `ff_mjpeg_decode_sof` — only 1 or 3 components are accepted for JPEG-LS (line 733–735 of mjpegdec.c), preventing a potential stride/linesize mismatch.

6. All bytestream reads use bytestream2 functions with internal bounds checking.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
