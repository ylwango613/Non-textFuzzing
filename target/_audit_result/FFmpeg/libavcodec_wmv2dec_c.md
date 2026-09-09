After thorough analysis of the entire `wmv2dec.c` file across all code paths:

- **`dxy` array index** (lines 194-195): `dxy = 2 * ((motion_y&1)<<1 | (motion_x&1)) + w->hshift`. `hshift` is 0 or 1 (`get_bits1`), initial `dxy` is 0-3, so final `dxy` is 0-7, within `put_mspel_pixels_tab[8]`. Safe.
- **`abt_type_table[n]`** (lines 278, 634): `n` is 0-5, array is `[6]`. All writes/reads in range. `abt_type` only ever set via `decode012()` (returns 0/1/2), matching the switch cases.
- **`abt_block2[n]`** (line 648): `n` is 0-5, array is `[6][64]`. Safe.
- **extradata** (lines 390-393): `extradata_size < 4` guard before `init_get_bits(..., 32)`. Safe.
- **`slice_height`** (lines 405-408): `code == 0` explicitly rejected before division. Safe.
- **`parse_mb_skip` mb_type writes**: loops bounded by `mb_height`/`mb_width`, stride indexing stays within the `mb_stride * mb_height` allocation.
- **`memset` in secondary header** (line 459): `mb_height * mb_stride * sizeof(uint32_t)` - dimensions are constrained by FFmpeg's codec-level dimension checks upstream.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
