I have now read the entire file in batches (0-500, 500-1000, 1000-1458), examined the related headers (vp9dec.h, vp9shared.h), the allocations in vp9.c, and the scan/neighbor tables in vp9data.c. Let me summarize the key checks performed:

**Batch 1 (lines 0-500) — decode_mode findings:**
- `memset(&s->above_segpred_ctx[col], 1, w4)` uses w4 = FFMIN(s->cols-col, bw4) — stays in bounds.
- `left_segpred_ctx[8]` / `left_skip_ctx[8]` / `left_mode_ctx[16]` — block alignment guarantees `row7 + h4 ≤ 8` always.
- `above_mode_ctx[col*2 ± off]`, `left_mode_ctx[row7 ± off]` — all within allocated s->sb_cols×16 entries.
- `inter_mode_ctx_lut[14][14]` — mode values bounded 0-13 by the VP9 tree decoder.
- `above_mv_ctx[col*2+n]` loops verified: max index `col*2 + w4*2 - 1 ≤ s->cols*2 - 1 < s->sb_cols*16`.

**Batch 2 (lines 500-1000) — decode_coeffs_b_generic findings:**
- `cache[1024]` stack array: scan/nb tables are static constants; nb[i] always references the current scan[i] position (just written) or a prior position already written — no uninitialized read causes OOB.
- `cnt[band][nnz][...]` and `eob[band][nnz][...]`: nnz computed as `(1 + cache[...] + cache[...]) >> 1` giving 0-5 (from max cache value 5), within the [6] dimension.
- `STORE_COEF(coef, rc, ...)`: rc = scan[i] ∈ [0, n_coeffs-1]; buffer exactly sized to hold n_coeffs coefficients.
- `band_counts[b->tx]` and `band_counts[b->uvtx]`: both bounded to [0,3], within `band_counts[4][8]`.

**Batch 3 (lines 1000-1458) — ff_vp9_decode_block findings:**
- `block_base` allocation of `64*64 * bytesperpixel * sizeof(int16_t)` bytes: maximum offset `16 * 192 * bpp * 2 + 1024 * 2 * bpp` = exactly 8192×bpp bytes for 8bpp; same ratio holds for 16bpp.
- `eob_base` (256 bytes): max index n=255 for TX_4X4, exactly within bounds.
- `nb_block_structure`: at most s->cols × s->rows calls to ff_vp9_decode_block (one per 8-pixel cell), matching the allocation.
- `b->uvtx = b->tx - (condition)`: never negative (condition requires b->tx ≥ 1 to subtract 1).
- `lflvl->mask[0..1][y][0..3]`: y bounded by row7 + h ≤ 7 + block_h ≤ 7 (block alignment), always < 8.
- `lflvl->level[row7*8 + col7]`: bounded to [0,63].
- `feat[b->seg_id].lflvl[b->ref[0]+1][...]`: b->ref[0] ∈ {0,1,2}, index ∈ {1,2,3} ⊂ [0,3]. Fine.
- `segmentation.feat[b->seg_id]`: b->seg_id set via validated tree (0-7) or from a properly-filled segmentation_map (also 0-7).

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
