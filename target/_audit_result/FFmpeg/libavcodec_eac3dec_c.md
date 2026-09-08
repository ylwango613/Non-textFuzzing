After complete analysis of all 514 lines of `eac3dec.c` across all major functions, I investigated every suspicious pattern:

**`ff_eac3_apply_spectral_extension` (lines 56-149):**
- `copy_sizes[SPX_MAX_BANDS]` (17 elements): Worst-case `num_copy_sections` is constrained by `total_extension_bins / R + 1` ≤ 180/12 + 1 = 16, plus at most one zero-length section from a D-start first band → absolute max 17, matching the array size exactly. No overflow.
- `transform_coeffs` memcpy destinations: bounded by `dst_end_freq` (max 229) < AC3_MAX_COEFS (256). No OOB.
- Notch filter coeffs access: `bin` starts at `spx_src_start_freq - 2` ≥ 47; `coeffs[4]` max at 231 < 256. No OOB.

**`ff_eac3_decode_transform_coeffs_aht_ch` (lines 195-286):**
- `gaq_gain[AC3_MAX_COEFS]` (256 elements): For EAC3_GAQ_124, with max 253 qualifying bins, triggers = 85 → writes = 255 ≤ 255 (valid). No OOB.
- First-pass write condition (`bap > 7 && bap < end_bap`) and second-pass read condition (`hebap >= 8 && hebap < end_bap`) are equivalent. No uninitialized-memory read mismatch.
- `ff_eac3_bits_vs_hebap[20]`: max `hebap` ≤ 16 < 20. No OOB.
- `ff_eac3_gaq_remap_2_4_a/b[9][2]`: `hebap-8` ∈ [0,8], `log_gain-1` ∈ {0,1}. No OOB.
- `ff_eac3_spx_atten_tab[32][3]`: `spx_atten_code` = 5-bit field → 0-31. No OOB.

**`ff_eac3_parse_header` (lines 288-514):**
- All bitstream fields are either validated or written to properly bounded struct members. No overflows identified.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
