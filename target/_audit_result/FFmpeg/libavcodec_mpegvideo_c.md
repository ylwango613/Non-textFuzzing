After reading all 517 lines of `mpegvideo.c` and performing targeted verification of the key arithmetic, allocations, and access patterns, here is the definitive conclusion:

**Key findings per analysis group:**

**Lines 191–353 (`ff_mpv_init_context_frame`):**
- `av_image_check_size` at line 370 calls `av_image_check_size2(..., INT64_MAX, ...)` which enforces the stride constraint `(8w + 1024)*(h + 128) < INT_MAX`. This bounds all derived sizes (`mb_width`, `mb_height`, `b8_stride`, `y_size`, `yc_size`) to well within `int` range — no integer overflow in size computations.
- The `p_field_mv_table` allocation (`av_calloc(mv_table_size, 4 * sizeof(*tmp))`) allocates `4 * mv_table_size` elements where `mv_table_size = (mb_height + 2) * mb_stride + 1`. The "+2" in `(mb_height + 2)` accounts for both the prefix padding (`mb_stride + 1` elements at the front) and unused tail in the last sub-table, so the last sub-table's max real access falls exactly at `4 * mv_table_size - 1`. The allocation is precisely correct.
- All other `av_mallocz`/`av_calloc` calls are safe: sizes bounded by the image dimension checks.

**Lines 447–470 (`ff_clean_intra_table_entries`):**
- Negative `block_index` values at border macroblocks (e.g., mb_x=0: `block_index[0] = -2`) are safe because `dc_val = dc_val_base + b8_stride + 1` pre-pads the buffer for exactly these offsets.

**Lines 472–500 (`ff_init_block_index`):**
- The unsigned subtraction `(s->mb_x - 1U) << width_of_mb` is intentional: cast to `int` gives a bounded negative pointer offset (border pre-load); not exploitable.

**Lines 99–117 (`ff_mpv_init_duplicate_contexts`):**
- `av_memdup(s, slice_size)` with `slice_size = s->slice_ctx_size` (struct size). No external input controls `slice_size`.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
