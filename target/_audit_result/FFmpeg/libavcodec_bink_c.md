Now let me verify the `list_end` bounds in `read_dct_coeffs` and `read_residue` (both declare `coef_list[128]`/`mode_list[128]`):

- `read_dct_coeffs`: 6 initial entries (list_end→70). Mode 1 adds 3 children per trigger; the 3 mode-0 seeds each generate one mode-1, each adding 3 entries → max list_end = 70+9 = 79 < 128 ✓  
- `read_residue`: 4 initial entries (list_end→68), same mode-1 expansion → max 77 < 128 ✓  
- `coef_count`/`nz_coeff_count`: each of the 64 coefficient positions processed at most once → max 64, fits `coef_idx[64]`/`nz_coeff[64]` ✓  
- `init_bundles`: `bw*bh` cannot overflow because `av_image_check_size` bounds area; `av_calloc` handles overflow internally ✓  
- RAW_BLOCK `cur_ptr` advances: per-source buffer is `blocks*64` bytes; total RAW_BLOCK consumption is bounded by total blocks × 64 = buffer size ✓  
- `get_value` lacks explicit `cur_ptr < data_end` guard, but the allocation is sized for maximum possible reads ✓  
- Motion vector `ref_end` boundary math resolves exactly to the last valid frame byte ✓

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
