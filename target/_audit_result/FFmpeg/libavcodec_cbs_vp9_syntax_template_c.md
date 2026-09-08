I have now read the complete file (484 lines) in full and thoroughly examined:

- All array accesses: `ref_frame_idx` (3-bit → 0-7, array size 8), `ref_frame_sign_bias` (indices 1-3, array size 4), `loop_filter_ref_deltas`/`update_ref_delta` (i < 4, array size 4), `segmentation_tree_probs` (i < 7, array size 7), `segmentation_pred_prob` (i < 3, array size 3), `feature_enabled/value/sign` (i < 8, j < 4, array sizes match), `frame_sizes` (i ≤ `frames_in_superframe_minus_1` which is 3 bits → max 7, array size 8).
- No `av_malloc`/`memcpy`/`alloc` calls exist in the syntax template itself.
- The `tile_info` loops are bounded by uint16_t `sb64_cols` (max ~1025 from max 16-bit frame dimensions), preventing any shift overflow or infinite loop.
- All bitstream-derived values are constrained by their read widths before being used as array indices.
- The `cbs_vp9_split_fragment` in cbs_vp9.c properly validates `frame_sizes` against `frag->data_size` before use.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
