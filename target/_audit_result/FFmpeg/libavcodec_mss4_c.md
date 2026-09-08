After thorough multi-pass analysis of all 628 lines and all referenced functions, here is the complete picture:

**Batch 1 (lines 1–270): `mss4_decode_dct` / `mss4_decode_dct_block`**
- `ff_zigzag_direct[pos]` where pos < 64 is always verified before use (`if (pos >= 64) return -1;`) — no OOB.
- `dc_cache[4][4]`: j=0,1 for luma, `i+1` = 2,3 for chroma — all within `[0..3]`.
- `prev_dc[0]` max index = `2*mb_width - 1`, allocated as `FFALIGN(avctx->width,16)/4 = 4*mb_width` — no OOB.

**Batch 2 (lines 271–429): `mss4_decode_image_block`**
- `split = get_bits(gb, 4)` returns 0–15; after conditional `split++`, split is at most 16.
- `prev_mode[16]`: first half writes indices 0..split-1 ≤ 15; second half writes `split+k` where `k < 16-split`, so max index = 15. No OOB.
- `imgbuf[3][256]` (16×16): each of 16 rows writes exactly 16 bytes per channel regardless of mode (split + (16-split) = 16), totalling exactly 256 per channel. No overflow.
- `vec_pos` in `get_value_cached`: guarded by `if (vec_pos < vec_size)` — prevents OOB even when `read_vec_pos` increments beyond range.

**Batch 3 (lines 430–628): `mss4_decode_frame` / `mss4_decode_init`**
- `av_malloc_array(dc_stride[i], sizeof(**)` with `dc_stride[i] = FFALIGN(avctx->width,16) >> (2+!!i)` — sized correctly for all subsequent accesses.
- Width validation `width <= avctx->width` ensures macroblock loop stays within frame bounds.
- `ff_mss34_dct_put` writes 8×8 blocks; max column offset `FFALIGN(width,16)–1 ≤ linesize[0]` due to FFmpeg's ≥32-byte linesize alignment guarantee.
- The `8*buf_size < 8*HEADER_SIZE + mb_width*mb_height` check (line 503) can overflow if `mb_width*mb_height > INT_MAX/8`, but this is guarded upstream by `av_image_check_size2` which enforces `max_pixels`.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
