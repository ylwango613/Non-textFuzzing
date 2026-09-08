**Complete analysis results:**

**Allocation (line 468):** `av_calloc(slice_width, 384*2)` — `slice_width` is capped ≤ 32 by the init loop (`mb_width / i ≤ 32`). Max 24576 bytes. No overflow; `av_calloc` checks internally too.

**data_ptr layout:** offsets {0, 64, 96, 288} × slice_width in int16_t units match per-MB num_coeffs {64, 32, 192, 96}, summing to AIC_BAND_COEFFS=384. Correct.

**Scan table bounds for every band/force_chroma combo:**
- band=0 (luma, 64 coeffs): aic_y_scan or aic_c_scan — max scan value 63, buffer 64 entries. ✓
- band=1 (chroma, 32 coeffs): aic_c_scan — only indices 0-31 used, max scan value in those 32 entries = 31. Buffer 32 entries. ✓
- band=2 (luma_ext, 192 coeffs): aic_y_ext_scan or aic_c_ext_scan — max scan value 191. Buffer 192 entries. ✓
- band=3 (chroma_ext, 96 coeffs): aic_c_ext_scan — first 96 entries have max value 95. Buffer 96 entries. ✓

**Skip logic in `aic_decode_coeffs`:** `idx` is checked against `num_coeffs` before any `dst[scan[idx]]` write. `val` is bounded to < 0x10000 before use as an index offset. ✓

**`recombine_block` pointer advances:** verified for both interlaced (blocks 0-1: base+32, ext+32; blocks 2-3: ext+64 each; total ext=192) and non-interlaced (base+16, ext+48 per block × 4 blocks = base+64, ext+192). Matches band buffer sizes precisely. ✓

**`slice_size` check (line 419):** `bytestream2_get_le16 * 4 ≤ 262140`; validated against `buf_size - off` before use. ✓

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
