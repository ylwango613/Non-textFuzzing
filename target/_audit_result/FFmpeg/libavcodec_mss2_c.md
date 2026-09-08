After thorough multi-pass analysis of `/data/ylwang/non-textfuzz/target/FFmpeg/libavcodec/mss2.c` (914 lines) and its dependencies (`mss12.c`, `mss2dsp.c`, `mss12.h`), examining every memory-safety-relevant code path:

**Batch 1 (lines 1–240):** Arithmetic coder (`arith2_normalise`, `arith2_get_number`, `arith2_get_prob`), `decode_555` — all repeat/skip logic properly guarded; `(unsigned)repeat` cast avoids FFMIN sign issue; region bounds validated before `dst` offset arithmetic.

**Batch 2 (lines 241–465):** `decode_rle` VLC + RLE loop — alphabet is bounded (269–270 symbols); `pal[last_symbol]` only accessed when `0 ≤ last_symbol ≤ 255`; clip region x/y/clipw/cliph validated against w/h before pointer arithmetic. `decode_wmv9` — `init_get_bits8` bounds the bit reader; blit functions receive x/y/w/h from arith-coder which ensures `x+w ≤ width`, `y+h ≤ height`.

**Batch 3 (lines 466–808) — `mss2_decode_frame`:** `WMV9codedFrameSize` (AV_RL24, max 0xFFFFFF): no check that it ≤ `buf_size-3`, so after the call `buf` can advance past end and `buf_size` goes negative. However, (a) the bit-reader inside `decode_wmv9` is bounded by `buf_size-3`, so no OOB read occurs inside; (b) the pointer `buf` is never dereferenced after update — the next-iteration guard `buf_size < 4` fires (short-circuit before `AV_RL24(buf)`), and if it's the last rectangle nothing reads from `buf` thereafter. Net: a logic error but no exploitable memory-safety violation.

`calc_draw_region` analysis: proved algebraically that after both COMPARE passes, `draw.right ≥ draw.left` always; zero-width handled safely by `decode_pivot` returning −1 and `memset(..., 0)`.

**Batch 4 — `mss12.c` helpers:** `copy_rectangles`, `motion_compensation` — all have explicit bounds checks; `decode_region_intra` `memset(dst, pix, width)` — width ≥ 0 proven above; `decode_pixel_in_context` `src[-1]` / `src[-stride]` — never called at (i=0, j=0), so always in-bounds. `mss2_decode_init` pal_pic allocation: `pal_stride × height ≤ 4111 × 4096 ≈ 16 MB`, no overflow.

**`mss2dsp.c` — blit & upsample:** `upsample_plane_c` `w += (w & 1)` stays within `f->linesize[0]` (MB-aligned allocation ≥ w+1); all row/column indices verified within frame allocation.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
