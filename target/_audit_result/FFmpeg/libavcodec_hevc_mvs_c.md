After thorough analysis of `/data/ylwang/non-textfuzz/target/FFmpeg/libavcodec/hevc/mvs.c` across all 784 lines, examining:

- **Merge candidate list bounds**: `MRG_MAX_NUM_CANDS = 5`, `max_num_merge_cand` validated to `[1,5]` in hevcdec.c:1033, `merge_idx` decoded as unary code bounded by `max_num_merge_cand - 1` (cabac.c:741). All array writes (`mergecandlist[nb_merge_cand]`) bounded by `max_num_merge_cand ≤ 5`. B2 spatial candidate guarded by `nb_merge_cand != 4` with at most 4 prior candidates. No OOB.

- **Combined bi-predictive index table**: `l0_l1_cand_idx[12][2]` accessed with `comb_idx` bounded by `nb_orig_merge_cand * (nb_orig_merge_cand - 1)` where `nb_orig_merge_cand < max_num_merge_cand ≤ 5` → max `4*3 = 12` iterations, exactly fitting the table. Values in table (0-3) all within populated `mergecandlist`. No OOB.

- **TAB_MVF array accesses**: All `(y_pu * min_pu_width + x_pu)` indices validated via SPS width/height bounds checks. Availability flags (`cand_left`, `cand_up`, etc.) short-circuit access before negative coordinates can reach the macro.

- **Division by zero in `mv_scale()`**: `td = col_poc_diff` is guarded by `!col_poc_diff` pre-check; `mv_scale` is only called in the else branch ensuring `td ≠ 0`.

- **`RefPicList.list[]` access via `ref_idx`**: `MvField.ref_idx` is `int8_t` set by the decoder with validated values `[0, num_ref_idx_active-1]`; `HEVC_MAX_REFS = 16` matches the list array sizes.

- **MVP candidate list**: `mvpcand_list[2]` accessed with `mvp_lx_flag` which is a 1-bit syntax element (always 0 or 1). No OOB.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
