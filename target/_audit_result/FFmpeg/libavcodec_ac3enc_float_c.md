The Python script confirms `num_cpl_bands` is at most 10 across all valid parameter combinations, which is well within the `energy[...][16]` bound. All rematrix band table accesses (`bnd+1` up to index 4 in a 5-element table) are also within bounds.

After complete analysis of `ac3enc_float.c` (131 lines), `ac3enc_template.c`, and the core `ac3enc.c` allocation/initialization code:

- `scale_coefficients()`: buffer offsets are tight but correct — both `cpl=0` and `cpl=1` cases access exactly to `total_coefs-1`.
- `apply_channel_coupling()`: `energy[blk][ch][bnd]` third-dimension is 16; max `num_cpl_bands` proven to be 10 via static `ff_eac3_default_cpl_band_struct` table — no OOB.
- `allocate_buffers()`: all multiplications use small bounded constants (AC3_MAX_COEFS=256, num_blocks≤6, channels≤7); no integer overflow.
- `copy_input_samples()`: only called when `frame->nb_samples < frame_size`, so destination buffer is never under-allocated.
- `apply_mdct()`: `planar_samples` (1 block) and `extended_data` (≥frame_size blocks) access patterns are fully bounded.
- All rematrix band table accesses are within the 5-element `ff_ac3_rematrix_band_tab`.

This is an **encoder**, not a decoder — the code processes internally-generated PCM samples from a prior decode step, with all structural parameters (block count, channel count, coupling layout) fixed at `avcodec_open2()` time and validated by `validate_options()`. There is no path by which attacker-controlled bytes in a media container can drive the size calculations or buffer indices used in this encoder.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
