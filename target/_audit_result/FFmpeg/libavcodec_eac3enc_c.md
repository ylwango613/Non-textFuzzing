I have now fully analyzed the file. Here is my assessment:

- `eac3enc.c` is 285 lines and is a pure **encoder** (not a decoder). It contains no direct parsing of external/container data.
- The 6-dimensional LUT access in `ff_eac3_get_frame_exp_strategy()` (line 81) uses `s->exp_strategy[ch][0]-1` as the first index. Block 0 is always set to `EXP_NEW` (=`EXP_D15`=1) at ac3enc.c:672 and can only be updated to values from `exp_strategy_reuse_tab` (values 1, 2, 3), so the index is always 0–2 for the `[3]` first dimension.
- Dimensions 1–5 of the LUT accept 0–3, matching the `{EXP_REUSE, EXP_D15, EXP_D25, EXP_D45}` = `{0,1,2,3}` value range, with no out-of-bounds possibility.
- The `exponent_group_tab` usage at ac3enc.c:1811 is guarded by an `EXP_REUSE` check at line 1804 (`continue`), preventing the `-1` index.
- `eac3_output_frame_header()` writes to a buffer sized to `s->frame_size`, which is computed to fit all header bits before any `put_bits` calls.
- All complex allocation and encoding logic is in `ff_ac3_float_encode_init`/`ff_ac3_encode_frame`/`ff_ac3_encode_close` (ac3enc.c), not in this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
