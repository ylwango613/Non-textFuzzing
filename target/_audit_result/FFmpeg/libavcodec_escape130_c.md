All chroma values written via `*new_cb = cb` have `cb ∈ [0, 31]` (either from `get_bits(&gb, 5)` or masked with `& 31`), matching the 32-entry `chroma_vals[]` table. The `ya` pointer walks exactly `total_blocks = width*height/4` slots — equal to the allocation at line 128. Framework-level checks in `av_image_check_size2` cap `w*h` at ~268 M, keeping `w*h*3/2` within `int` range and preventing underallocation. All table indices (`sign_selector` 6-bit → [0,63] into `sign_table[64]`, `difference_selector` 2-bit → [0,3] into `offset_table[4]`, `adjust_index` 3-bit → [0,7] into `luma_adjust[8]`/`chroma_adjust[2][8]`) are properly bounded. The `old_y[old_y_stride]` stride-ahead reads at the final row pair land within the last row of the allocated Y plane.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
