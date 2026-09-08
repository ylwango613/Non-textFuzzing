With `MAX_TB_SIZE = 32` confirmed, I can now finalize my analysis of all critical access patterns.

**Key bounds verification (MAX_TB_SIZE = 32):**

- `left_array[81]`, pointer `left = left_array + 1` → valid range `left[-1..79]`
- `top_array[81]`, pointer `top = top_array + 1` → valid range `top[-1..79]`
- `filtered_left_array[65]`, pointer `filtered_left_array + 1` → valid range `[-1..63]`
- `filtered_top_array[65]`, pointer `filtered_top_array + 1` → valid range `[-1..63]`
- `ref_array[100]`, `ref_tmp = ref_array + size` (max 32) → negative refs go at most to `ref_array[0]`

**Specific checks done:**

1. `ref_filter_strong` hardcoded index 63: `left[63] = left_array[64]` ✓ (within [0..80]); `filtered_top[63] = filtered_top_array[64]` ✓ (within [0..64])
2. `ref_filter_3tap` accesses `left_p[-1]` = `left_array[0]` ✓ (intentional offset)
3. `pred_angular` `ref_tmp[x]` for negative x: minimum is `ref_array[size + last]` = `ref_array[0]` at worst ✓
4. `pred_angular` `left[...]` access via inv_angle formula: max index computed to `left[31]` ✓
5. `intra_pred_angle[mode-2]`: array has exactly 33 elements (17+16), modes 2-34 → indices 0-32 ✓
6. `inv_angle[mode-11]`: 15 elements, accessed only for modes 11-25 → indices 0-14 ✓
7. `ref_filter_3tap[log2_size-3]`: guarded by `size != 4`, so log2_size ∈ {3,4,5} → indices 0-2 ✓ for the 3-element array
8. `EXTEND_UP_CIP` potential underflow: requires `size_max_y ≡ 1 or 2 (mod 4)`, but HEVC spec mandates `pic_height_in_luma_samples % MinCbSizeY == 0` (MinCbSizeY ≥ 8), so `size_max_y` is always a multiple of 4, making the last loop iteration i=3 → `ptr[0]` ✓
9. Negative-index `tab_mvf` accesses via `IS_INTRA(-1,y)` or `IS_INTRA(x,-1)`: protected by neighbor availability flags (`cand_left=0` at x0=0, `cand_up=0` at y0=0)

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
