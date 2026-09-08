After thorough analysis of all four functions in `h2656_sao_template.c` and their call chains, I've verified:

- **`sao_band_filter`**: `(k + sao_left_class) & 31` is always 0-31 (safe); `sao_offset_val[k+1]` accesses indices 1–4 within the declared 5-element `int16_t offset_val[3][5]` array; `(src[x] >> shift) & 31` is also bounded 0-31.
- **`sao_edge_filter`**: `eo` is a 2-bit CABAC-decoded value (0–3), indexing a `pos[4][2][2]` array safely; `edge_idx[2 + diff0 + diff1]` is always 0–4 for a 5-element array; `sao_offset_val[offset_val]` uses values 0–4 within the 5-element offset array.
- **`sao_edge_restore_0` / `sao_edge_restore_1`**: `c_idx` is validated by callers (0–2 for 3-element arrays); `vert_edge[2]`, `horiz_edge[2]`, and `diag_edge[4]` are fixed-size arrays in the caller with sizes matching all access indices; `stride_src` in `sao_edge_filter` is a compile-time constant and the edge_emu_buffer is pre-padded to accommodate negative-offset accesses.

No externally triggerable memory safety vulnerability was identified.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
