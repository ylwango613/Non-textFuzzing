Based on my comprehensive multi-pass analysis of `cbs_h264_syntax_template.c` (1295 lines), I examined:

**Batch 1 (lines 1–400):** `nal_unit_header`, `scaling_list`, `hrd_parameters`, `vui_parameters`, `sps`. All array accesses bounded: `delta_scale[64]` accessed up to 63 (size_of_scaling_list ∈ {16,64}), HRD loop bounded by `cpb_cnt_minus1 ≤ 31` against `[H264_MAX_CPB_CNT=32]` arrays, `offset_for_ref_frame[256]` accessed up to `num_ref_frames_in_pic_order_cnt_cycle ≤ 255`.

**Batch 2 (lines 400–850):** `pps`, SEI functions. The `pic_size` = `(w+1)*(h+1)` is `unsigned int` (max 1,056²=1,115,136 given SPS constraints). The `allocate(current->slice_group_id, current->pic_size_in_map_units_minus1 + 1)` macro expands to `av_buffer_allocz(size + AV_INPUT_BUFFER_PADDING_SIZE)`. `pic_size_in_map_units_minus1` is `uint16_t` (max 65535), so allocation ≤ 65,536+64 bytes. The subsequent loop `for (i = 0; i <= current->pic_size_in_map_units_minus1; i++)` uses the **same** truncated field — both allocation and loop bound are consistent, no OOB write. SEI arrays (`intensity_interval_lower_bound[3][256]`, `comp_model_value[3][256][6]`) are accessed within their declared sizes.

**Batch 3 (lines 850–1295):** `ref_pic_list_modification`, `pred_weight_table`, `dec_ref_pic_marking`, `slice_header`. `rplm_l0/l1[H264_MAX_RPLM_COUNT=33]` arrays accessed up to `H264_MAX_RPLM_COUNT-1`. `luma_weight_l0[H264_MAX_REFS=32]` accessed up to `num_ref_idx_l0_active_minus1 ≤ 31`. `mmco[H264_MAX_MMCO_COUNT]` accessed up to 32 times with an explicit overflow guard at line 1044.

**Key macro verification:** `ff_cbs_read_ue_golomb` writes into a local `uint32_t`, validates the range, then the `xue` macro assigns `var = value`. When `var` is a `uint16_t` field and `value > UINT16_MAX`, truncation occurs but both allocation size and loop bound use the same truncated field — no buffer overflow results.

**Dynamic bit-width reads:** All `ub(width, name)` calls use widths bounded by SPS-constrained fields (max 32 bits), all safely within `uint32_t` range and target field sizes.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
