After a thorough multi-pass audit of `/data/ylwang/non-textfuzz/target/FFmpeg/libavcodec/snowdec.c` and all referenced code (snow.c, snow.h, snow_dwt.c, snow_dwt.h), here is the complete analysis summary:

**Pass 1 – `unpack_coeffs` (lines 76–179):** `b->x_coeff` is allocated as `(b->width+1)*b->height+1` elements. The write pattern is at most `b->height` end-of-row markers + `b->height*b->width` coefficients + 1 final marker = exactly `b->height*(b->width+1)+1`. Tight but correct, no overflow.

**Pass 2 – `decode_subband_slice_buffered` (lines 263–302):** Reads `b->x_coeff[new_index]` in a while-loop terminating on the end marker (`x >= w`). End markers are always placed by `unpack_coeffs` before this function runs; `new_index` never escapes the buffer.

**Pass 3 – `b->state[context+2]` in `unpack_coeffs` (line 124):** `context = av_log2(...)` with max argument ≈262,136 → `av_log2 = 17`. So `b->state[19]` (max) from `state[34][32]` array — within bounds. The `get_symbol2` loop accesses `state + 4 + log2` with max offset 31 within a 32-byte row — within bounds.

**Pass 4 – `decode_q_branch` block array indexing (lines 304–368):** Block array allocated as `b_width*b_height * 4^block_max_depth` elements. With `block_max_depth` validated ≤1, recursive indices stay within bounds.

**Pass 5 – `decode_header` validation (lines 448–571):** `spatial_decomposition_count` bounded by `MAX_DECOMPOSITIONS=8`; `block_max_depth` ≤1; `mv_scale` ≤256; `qbias` ≤127; `max_ref_frames` < 8; width < 65536.

**Pass 6 – `avmv` allocation (lines 662–673):** Uses `av_size_mult` to prevent integer overflow, and increments stay ≤ `mb_w*mb_h` = allocated count.

**Pass 7 – `scratchbuf` (snow.c:546–548 + add_yblock):** The interleaving layout is intentional — when `src_stride ≥ 7*MB_SIZE`, blocks are placed 16 bytes apart and rows interleave in memory; the scratchbuf is sized `(2*w+256)*7*16` to accommodate all writes within bounds.

**Pass 8 – `block_state` accesses (decode_q_branch):** Max indices computed: `ref_context ≤ 16` → index 1664 < 4224; `mx_context ≤ 32` → index 1152 < 4224. Within `block_state[4224]`.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
