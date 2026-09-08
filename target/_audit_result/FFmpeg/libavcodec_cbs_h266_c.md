After reading all 809 lines of `cbs_h266.c` and all 3563 lines of `cbs_h266_syntax_template.c` in multiple batches, plus checking every array declaration, loop bound, and allocation in the call chain, here is the final result:

**All array accesses are properly bounded:**
- `gci_reserved_bit[255]`: loop max 249 iterations — safe
- `general_sub_profile_idc[256]`: `ptl_num_sub_profiles` u(8) max 255 — safe  
- `vps_profile_tier_level[256]`: `vps_num_ptls_minus1` u(8) max 255, loop ≤256 iter — safe  
- `vps_ols_output_layer_flag[257][64]`: outer index ≤256, inner ≤63 — safe  
- `sh_entry_point_offset_minus1[4050]`: `num_entry_points > VVC_MAX_ENTRY_POINTS` check aborts before write — safe  
- `col_width_val[30]`/`row_height_val[990]`: `i == VVC_MAX_TILE_COLUMNS/ROWS` guard inside while loop — safe  
- `slice_height_in_ctus[1000]` / `slice_top_left_ctu_x[1000]`: `i + num_slices_in_tile > pps_num_slices_in_pic_minus1 + 1` check aborts early — safe  
- `pps_exp_slice_height_in_ctus_minus1[1000][990]`: bounded by `row_height_val ≤ 792 < 990` — safe  

**VVCC header parsing (`cbs_h266_split_fragment`):** all `bytestream2_skip` calls are clamped to buffer end; NAL size checks (`bytestream2_get_bytes_left < size`) prevent OOB reads.

**`num_entry_points` underflow (line 3525):** `uint32_t num_entry_points--` when zero yields `UINT32_MAX`, caught immediately by `> VVC_MAX_ENTRY_POINTS` → returns `AVERROR_PATCHWELCOME`, no memory corruption.

**One logic bug found (not memory-safety):** `ols_timing_hrd_parameters` at lines 634–638 both writes `general_nal_hrd` and `general_vcl_hrd` paths into `&current->nal_sub_layer_hrd_parameters` (copy-paste: the VCL path should use `vcl_sub_layer_hrd_parameters`). This causes incorrect HRD parsing, not memory corruption.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
