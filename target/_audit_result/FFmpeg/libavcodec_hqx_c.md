After thorough analysis of the complete file and all dependencies, I have found no practically exploitable memory safety vulnerabilities:

- `decode_block`: `pos` bounds check (`pos > 63`) before `ff_zigzag_direct[pos]`; AC run values max 65 from VLC table, no overflow risk. The `lev * q` multiplication with high AC-index bits is intentional and the upper bits are correctly truncated on `int16_t` store.
- `put_blocks`: `x`, `y` come from `mb_x * 16` / `mb_y * 16` within `decode_slice`, which is bounded to `[0, coded_width)` × `[0, coded_height)` by the `num_mbs` invariant.
- `decode_slice`: Division-by-zero guards hold: `grp_h_rest == 0` → `loc_row >= grp_v_edge` branch unreachable; `grp_v_rest == 0` → `mb_x >= grp_h_edge` branch unreachable. All `blk_addr < num_mbs`.
- Frame allocation: `ff_thread_get_buffer` failure is checked before `execute2`.
- `slice_off` validation: per-thread monotonicity check covers all adjacent pairs, no OOB pointer possible.
- `hqx_quants` / `dc_vlc` accesses: bounded by file-embedded constants and `dcb_code & 3` check.
- `hqx_idct_put`: writes exactly 8×8 samples with correct stride arithmetic.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
