After completing a thorough multi-pass analysis of all 1616 lines of `cabac.c` plus related headers and callers:

**Batch 1 (Lines 1–600):** `cabac_init_state` `init_type` is constrained to 0–2 (safe). `GET_CABAC` offsets for all simple decode functions verified against their allocated bin counts and the 199-element `cabac_state` array — all within bounds.

**Batch 2 (Lines 600–1200):** `cabac_bypass_bits` / `cabac_unary_prefix` use arithmetic that stays within `uint64_t`. `coeff_abs_level_remaining_decode` has an early-exit check when `prefix_minus3 + rc_rice_param > 22`. Although large `rc_rice_param` (via `stat_coeff/4` with persistent Rice adaptation) can cause `prefix << rc_rice_param` signed-integer UB, the result feeds `int64_t trans_coeff_level` which is then FFMIN/FFMAX-clamped to `int16_t` range, preventing any downstream memory write beyond the `coeffs[]` buffer.

**Batch 3 (Lines 1200–1616):** 
- `SCAN_HORIZ`/`SCAN_VERT` are set by the caller **only** when `log2_trafo_size < 4` (verified in hevcdec.c:1373), so `horiz_scan8x8_inv[last_y][last_x]` is always accessed with indices ≤ 7. 
- `significant_coeff_flag_idx[16]`: maximum fill is 16 entries (0–15), array is 16 elements — no overflow.
- `ctx_idx_map[3][5*16]` offsets are bounded by the verified `prev_sig` range (0–3) and `n` range (1–15): max index is `ctx_idx_map[2][64+15]` = index 79, within the 80-element slice.
- `diag_scan8x8_inv[y_cg_last_sig][x_cg_last_sig]` for 32×32: `x_cg_last_sig = last_significant_coeff_x >> 2 ≤ 31>>2 = 7` — valid for [8][8].
- `edge_emu_buffer` cast to `int16_t*`: 11 360 bytes >> 2048 bytes needed for 32×32 coefficients.
- All remaining CABAC context index computations produce values ≤ 178 < HEVC_CONTEXTS=199.

No exploitable memory-safety vulnerability found in this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
