After reading the full `ivi.c` (all ~1400 lines) in batches, cross-referencing `ivi.h`, `indeo4.c`, `indeo5.c`, and `libavutil/imgutils.c`, I performed the following targeted checks:

**1. `buf_size` uint32_t overflow in `ff_ivi_init_planes` (lines 331–333)**
`buf_size = width_aligned * height_aligned * sizeof(int16_t)` uses `uint32_t` math. I tested whether overflowing this to a tiny allocation could enable an OOB write downstream. However, `av_image_check_size2` at line 301–303 applies the guard `stride * (h + 128ULL) >= INT_MAX` (where `stride ≈ w + 1024` for YUV410P). This limits `w * h < ~2^28`, making `width_aligned * height_aligned * 2 < UINT32_MAX`. The overflow is provably unreachable.

**2. `tile->ypos * pitch` signed int overflow in `ivi_process_empty_tile` (line 861)**
Both variables are `int`; with large enough values this would wrap and produce an OOB pointer for the `memcpy`. But since `av_image_check_size2` limits `w * h < INT_MAX/8`, all `tile->ypos * pitch` products stay well below `INT_MAX`. Unreachable.

**3. `band->num_corr` OOB in `decode_band` (lines 981–989)**
`num_corr` is validated to ≤ 61 before storing in `band->corr[61*2]` in both `indeo4.c:421` and `indeo5.c:408`. Both `idx1/idx2` are `uint8_t` (0–255), safely indexing `runtab[256]`/`valtab[256]`. No issue.

**4. `rvmap_sel` OOB (`ivi.c:978`)**
`rvmap_sel = get_bits(gb, 3)` → 0–7, or hardcoded 8. Array `rvmap_tabs[9]` covers indices 0–8. Safe.

**5. `scan_pos` / `trvec[pos]` OOB in `ivi_decode_coded_blocks`**
`scan_pos` is checked `< num_coeffs` before `band->scan[scan_pos]` is accessed (line 545–547). Scan table values (0–63 or 0–15) index into `trvec[64]`. Safe.

**6. `2 * band->bufsize` overflow in `prepare_buf`**
With bounded dimensions, `band->bufsize = buf_size/2 ≤ INT_MAX/4`, so `2 * bufsize` cannot overflow. Safe.

**7. Motion vector bounds**
`mb->mv_x/mv_y` are `int8_t`; the MB-boundary checks in `ivi_decode_blocks` (lines 667–688) and `indeo5.c:567–572` are comprehensive.

**Conclusion:** All integer-overflow, OOB-array, and OOB-pointer paths I identified are either provably unreachable (blocked by `av_image_check_size2`) or protected by explicit bounds checks. No exploitable memory-safety vulnerability was found.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
