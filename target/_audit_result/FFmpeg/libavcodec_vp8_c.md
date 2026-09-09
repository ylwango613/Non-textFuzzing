I've completed a thorough multi-pass analysis of all 3017 lines of `vp8.c` plus the relevant headers. Let me summarize the key findings from each area analyzed:

**Pass 1 (lines 1–499):** `update_dimensions()` allocations — all bounds consistent. `setup_partitions()` has proper underflow checks. `seg_map` allocation `mb_width * mb_height` uses `uint16_t` values (max 1024×1024 = ~1M, well within `int32`).

**Pass 2 (lines 499–998):** `vp7_decode_frame_header()` / `vp8_decode_frame_header()` — width/height masked to 14/12 bits before use. Header-size underflow checks present. `decode_splitmvs()` writes to `mb->bmv[n]` where n ∈ [0, num−1], num ≤ 16, bmv has 16 elements.

**Pass 3 (lines 998–1497):** `vp7_decode_mvs()` edge pointer arithmetic — yoffsets are all ≤ 0, max achievable `edge_y = mb_height` with `edge_x = 0`, which resolves to index `1 + (mb_width+1)*(mb_height+1) < (mb_width+2)*(mb_height+2)` (always in bounds). `decode_block_coeffs_internal()` — `probs[i+1][1]` when `i=15` computes an OOB pointer but the loop exits immediately before it's ever dereferenced.

**Pass 4 (lines 1497–1996):** `edge_emu_buffer` = 21×32 = 672 bytes. Maximum luma emulation: 16+5=21 rows × 32 bytes = 672 bytes (exactly fits). Chroma: max 8+5=13 rows × 32 = 416 bytes. All within bounds.

**Pass 5 (lines 1996–2495):** `top_nnz[mb_x]`, `top_border[mb_x+1]`, `seg_map + mb_xy` — all allocation sizes match access ranges. `vp8_mbsplits[partitioning]` — 5-row table, `partitioning` ∈ [0,4].

**Pass 6 (lines 2495–3017):** Reference frame null checks guard inter-frame decoding. `ff_zigzag_scan[0..15]` values all in [0,15] for `block[scan[i]]` access on `block[16]`.

After exhaustive analysis, no externally-triggerable memory safety vulnerability is found in this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
