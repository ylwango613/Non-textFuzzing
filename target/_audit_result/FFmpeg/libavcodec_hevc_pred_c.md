After thorough analysis of both `pred.c` and the included `pred_template.c`, with verification of:

- `intra_pred_angle[]` — 33 entries (indices 0-32), covering modes 2-34 correctly ✓
- `inv_angle[]` — 15 entries, only accessed when `angle < 0`, giving valid mode-11 range 0-14 ✓
- Stack arrays (`left_array`, `top_array`, etc.) all sized at `2 * MAX_TB_SIZE + 1 [+16]` = 65/81 elements; all negative-index accesses are safe because pointers are offset by +1 from the allocation ✓
- `ref_array` in `pred_angular` = `3 * 32 + 4 = 100` elements; maximum write at `ref_tmp[size+3]` = `ref_array[67]` for size=32 ✓
- `ref_filter_3tap[log2_size - 3]` call guarded by `size != 4`, so index is always 0-2 ✓
- `pred_planar[log2_size - 2]` / `pred_angular[log2_size - 2]` — `log2_size` in range 2-5, index 0-3 ✓
- `intra_pred_mode` values decoded from bitstream stay in HEVC-valid range 0-34 through the CABAC parser ✓

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
