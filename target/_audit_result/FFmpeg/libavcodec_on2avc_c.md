After exhaustive analysis of all 1032 lines plus related data files, my key findings for each vulnerability pattern:

**Pattern 1 - Integer overflow → alloc undersize**: The `num_frames > INT_MAX / ON2AVC_SUBFRAME_SIZE` check at line 869 guards correctly.

**Pattern 2 - Array OOB in band_type/band_run_end/band_scales/ms_info**: `ON2AVC_MAX_BANDS = 112` exactly matches the maximum `num_windows * num_bands` = 8×14 = 112 (WINDOW_TYPE_8SHORT). All array accesses stay within 0..111.

**Pattern 3 - on2avc_decode_quads non-multiple-of-4 band_size**: All band start tables (on2avc_swb_start_*) have differences that are multiples of 4, so the 4-at-a-time loop never overshoots.

**Pattern 4 - on2avc_read_ms_info negative offset**: `grouping[0]` is hardcoded to 1 (line 815), so `band_off - num_bands` is always non-negative before any non-grouped window is encountered.

**Pattern 5 - window_type OOB**: 3-bit field (0–7), modes arrays have exactly 8 entries.

**Pattern 6 - on2avc_decode_band_types integer underflow**: `num_bands - band - run_len ≥ 0` is maintained as an invariant at each do-while iteration.

**Pattern 7 - coeff_ptr total writes**: Sum of all band sizes for each mode equals exactly `ON2AVC_SUBFRAME_SIZE = 1024`, keeping coeff_ptr within `c->coeffs[ch]`.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
