After reading all 716 lines of `indeo4.c` in multiple passes and tracing through the full call chain into `ivi.c`, `ivi.h`, and `indeo4data.h`, here is my consolidated assessment:

**Batch 1 (lines 1–260): `decode_pic_hdr`**
- `pic_size_indx` (3-bit, 0–6) → `ivi4_common_pic_sizes[indx*2+1]`; array has 14 entries → max index 13. Safe.
- `av_image_check_size2` called with `AV_PIX_FMT_YUV410P` and `max_pixels` before any allocation. The `stride*(h+128) < INT_MAX` guard limits valid dimensions to ≈45 500×45 500, preventing `buf_size` uint32 overflow in `ff_ivi_init_planes`.
- `ff_ivi_init_planes`: `buf_size = width_aligned * height_aligned * 2` as uint32; never overflows within the size limit above.

**Batch 2 (lines 261–456): `decode_band_hdr`**
- `transform_id` (5-bit) checked against `FF_ARRAY_ELEMS(transforms)` (=18) and `!transforms[id].inv_trans` before use. Safe.
- `scan_indx` (4-bit, 0–14; 15 rejected) → `scan_index_to_tab[15]` (15 entries). Safe.
- `quant_mat` (5-bit, 0–30; 31 rejected, ≥22 rejected) → max valid index 21 in `quant_index_to_tab[22]`. Safe.
- `quant_index_to_tab[quant_mat] > 4 && blk_size==4` check prevents OOB into `ivi4_quant_4x4_*[5]`. Safe.
- `band->num_corr ≤ 61` enforced; `band->corr[61*2]` exactly fits. Safe.
- `is_empty=1` path: `intra_base/inter_base` set using inherited `quant_mat` which was validated on prior non-empty frame; always within bounds.

**Batch 3 (lines 457–627): `decode_mb_info` / `ivi_decode_blocks`**
- Motion vector bounds check (lines 607–612) validates reference position for both forward (`mb->mv_x/mv_y`) and backward (`mb->b_mv_x/b_mv_y`) in `ivi_decode_blocks` (lines 667–687). Safe.
- `buf_offs` (uint32) sub-block arithmetic: for blk=2, `buf_offs += blk_size * pitch`. Within max picture dimensions, never overflows uint32 or int. `min_size > buf_size` check at lines 710–714 returns `AVERROR_INVALIDDATA` before any OOB access for out-of-range `buf_offs`. Safe.
- `tile->num_MBs` consistency check at line 488 prevents iterating `mb++` past the allocated `tile->mbs` array. Safe.

**VLC / RV-map tables**
- `idx1/idx2` from `band->corr[]` are 8-bit values (0–255); `runtab[256]`/`valtab[256]` exactly accommodate. Safe.
- `ff_ivi_dec_huff_desc` frees old custom VLC before reallocating. No UAF/leak.

**Assertion-based crash in `ivi_mc`**: `av_assert0` (always enabled) fires if forward reference exceeds buffer; but forward MVs are validated in `decode_mb_info`/`ivi_decode_blocks` before reaching `ivi_mc`, so assertions should never fire. `ivi_process_empty_tile`'s MC path for edge macroblocks could theoretically reach an assertion failure for unusually large tiles, but this is abort()-based DoS only — no memory corruption — and is excluded per audit scope.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
