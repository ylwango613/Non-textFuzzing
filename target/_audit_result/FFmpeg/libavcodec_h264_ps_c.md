After a thorough multi-pass analysis of all 847 lines of `h264_ps.c`, examining:

- **Lines 105–130 (`decode_hrd_parameters`)**: `cpb_count` is bounded to ≤ 32U before the loop that indexes into `bit_rate_value[32]` and `cpb_size_value[32]`. The `cpr_flag` bitmask uses `get_bits1(gb) << i` where i can reach 31 (signed shift UB), but this has no memory-safety impact.
- **Lines 296–306 / 717–728 (SPS/PPS data copy)**: `data_size` is explicitly capped at `sizeof(sps->data) = 4096` before `memcpy(sps->data, gb->buffer, sps->data_size)`. Safe.
- **Lines 416–431 (`poc_cycle_length`)**: Validated against `FF_ARRAY_ELEMS(sps->offset_for_ref_frame) = 256` before use as loop bound.
- **Lines 447–468 (mb_width/mb_height)**: Overflow check `sps->mb_height >= INT_MAX / 2U` correctly uses unsigned comparison (int is promoted), then `av_image_check_size` provides a second gate.
- **Lines 595–646 (dequant tables)**: `max_qp = 51 + 6*(bit_depth_luma - 8)` ≤ 87 = `QP_MAX_NUM`, loop bound is `max_qp + 1 ≤ 88 = QP_MAX_NUM + 1`, matching buffer dimensions.
- **Lines 200–226 (`decode_scaling_list`)**: `size` is always 16 or 64 (hardcoded at all call sites); buffers in SPS/PPS structs match those sizes.
- **Lines 318–320 / 708–710**: `sps_id < MAX_SPS_COUNT (32)` and `pps_id < MAX_PPS_COUNT (256)` are validated before use as array indices.

All exploitable patterns (array-index-out-of-bounds, heap-underalloc via unbounded malloc, unchecked memcpy size) have proper mitigations in place. No memory-safety vulnerability was found.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
