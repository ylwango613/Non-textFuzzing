After completing all four batch reads of `cbs_av1.c` (1395 lines) and all batches of `cbs_av1_syntax_template.c` (2147 lines), plus reading `cbs_av1.h` for all struct definitions, I've verified:

**Checks performed:**

1. **tile_info array bounds** — `tile_start_col_sb`/`tile_start_row_sb` are both `[64]` (AV1_MAX_TILE_COLS = AV1_MAX_TILE_ROWS = 64). Loop indices are clamped by `max_log2_tile_cols/rows ≤ 6` → tile_cols/rows ≤ 64. No OOB.

2. **Film grain AR coefficients** — `ar_coeff_lag` is 2 bits (0–3); max `num_pos_luma = 2×3×4 = 24`, `num_pos_chroma ≤ 25`. Arrays `ar_coeffs_y[24]`, `ar_coeffs_cb/cr[25]` exactly cover these bounds. No OOB.

3. **Scalability metadata** — `temporal_group_size` is uint8_t (0–255); inner ref_cnt is 3 bits (0–7); `temporal_group_ref_pic_diff[255][7]` is exactly sized for j ≤ 6. No OOB.

4. **ITU-T T.35 / padding_obu payload** — `cbs_av1_get_payload_bytes_left` returns the 0-based index of the last non-zero byte (equals payload byte count before trailing bits). Allocation includes `AV_INPUT_BUFFER_PADDING_SIZE`. Read loop stays within allocated bounds. No OOB.

5. **OBU length validation** — `obu_length` is `uint64_t`, compared against `size` (size_t); mismatch returns AVERROR_INVALIDDATA. leb128 rejects values > UINT32_MAX.

6. **cbs_av1_write_obu memmove/memcpy** — guarded by `8 × obu_size ≤ put_bits_left(pbc)`, ensuring `data_pos + header_size + td->data_size ≤ buf_size`. No OOB write.

7. **assemble_fragment** — `size` is accumulated from callee-controlled units; no untrusted external input drives this in isolation.

8. **operating_point_idc indexing** — bounds-checked against `operating_points_cnt_minus_1` before array access.

9. **frame_size_with_refs** — `ref_frame_idx[i]` is always 0–7 (from 3-bit field or set_frame_refs which always picks a valid index). No negative-index deref.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
