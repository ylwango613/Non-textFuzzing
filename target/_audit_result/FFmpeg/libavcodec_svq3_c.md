After a comprehensive read of all 1613 lines of `svq3.c` in batches, plus inspecting related headers and grep results, here is my analysis of each suspected area:

**Batch 1 (lines 0–600):** Motion-vector prediction, `svq3_mc_dir_part`, `svq3_decode_block`. All scan-table accesses (types 1, 2, 3) stay within the 16-entry tables. Type 0 (`luma_dc_zigzag_scan` with large values up to 240) is never called from the decode path. No OOB found.

**Batch 2 (lines 600–1105):** `svq3_decode_mb` and `svq3_decode_slice_header`. In slice header: `length` is guaranteed ≥ 1 by the `(header & 0x60) == 0` guard. `slice_bytes = slice_length + length - 1` is always non-negative. The `slice_bytes * 8LL > get_bits_left` check gates the `memcpy`. The `memmove` source range `slice_buf[slice_length .. slice_length + length-2]` is within the `slice_bytes`-byte allocation. `mb2br_xy` accesses are all guarded by `mb_x > 0` / `mb_y > 0` checks.

**Batch 3 (lines 1105–1354):** `svq3_decode_extradata`. The overflow check `(uint64_t)watermark_width * 4 > UINT_MAX / watermark_height` correctly ensures `watermark_width * watermark_height * 4 ≤ UINT_MAX` (and intermediate product can't overflow `unsigned`). The `get_bits_left(&gb) <= 0` guard ensures `get_bits_count(&gb) ≤ size * 8`, so `offset = (get_bits_count + 7) >> 3 ≤ size`, making `size - offset ≥ 0` for the `uncompress` call.

**Batch 4 (lines 1354–1613):** `svq3_decode_frame`. The B-frame validation at lines 1481–1485 (`frame_num_offset == 0 || frame_num_offset >= prev_frame_num_offset → return -1`) guarantees `prev_frame_num_offset > 0` before the divisions in `svq3_mc_dir` (PREDICT_MODE). Allocation sizes (`big_mb_num`, `b4_array_size`, `intra4x4_pred_mode = mb_stride * 16`, `mb2br_xy`) are all within safe bounds given 12-bit dimension limits from SEQH extradata (max 4095 px).

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
