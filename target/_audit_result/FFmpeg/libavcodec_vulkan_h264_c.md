Based on my thorough multi-batch analysis of the entire 602-line `vulkan_h264.c` file, I examined:

1. **All array indexing** (`ref_slots[36]`, `refs[36]`, `ref_src[36]`, `h264_refs[36]`, `vkh264_refs[36]`): All bounded by `short_ref_count + long_ref_count ≤ ref_frame_count ≤ H264_MAX_DPB_FRAMES = 16 < 36`.

2. **Scaling list 8×8 loop** (lines 160–163, 266–269): `STD_VIDEO_H264_SCALING_LIST_8X8_NUM_LISTS = 2`, so only `h264_scaling_list8_order[0]=0` and `[1]=3` are accessed—both within the 6-element array. Destination `ScalingList8x8[2][64]` bounds respected.

3. **CPB loop** (lines 173–177): `sps->cpb_cnt` bounded to [1, 32] by h264_ps.c; both `sps->bit_rate_value[32]` and `vksps_vui_header->bit_rate_value_minus1[32]` have size 32. Safe.

4. **`minus1` arithmetic** (`cpb_cnt_minus1`, `bit_depth_*_minus8`, `log2_max_frame_num_minus4`, `num_ref_idx_*_minus1`, etc.): All underlying parsed fields have minimum value ≥ 1 (from `get_ue_golomb(gb) + 1` / `get_bits(gb, N) + 1` patterns in h264_ps.c). No underflow.

5. **`pic_height_in_map_units_minus1`** (line 223): `sps->mb_height` was already multiplied by `(2 - frame_mbs_only_flag)` at parse time; the division reverses this. Minimum result is 0. Safe.

6. **SPS/PPS param loop** (lines 337–355): Iterates `FF_ARRAY_ELEMS(sps_list) = 32` / `FF_ARRAY_ELEMS(pps_list) = 256` with destination arrays sized identically. Safe.

7. **`vk_h264_end_frame` null pointer** (lines 562–567): `hp->ref_src[i]` can only be NULL if the reference-filling loops partially misfired—no normal code path produces that.

No exploitable memory-safety vulnerability was found in this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
