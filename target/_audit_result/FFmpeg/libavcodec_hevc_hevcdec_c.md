I have now completed a thorough 7-batch reading of all 4311 lines of `hevcdec.c`, plus inspection of key header files and related code. Let me summarize the key areas I investigated:

**Batch 1 (lines 0-600):** `pic_arrays_init` SAO buffer allocations use `int` arithmetic `(w * 2 * sps->ctb_height) << sps->pixel_shift`. Within HEVC spec limits (max width 16384, ctb_height ≤ 1024, pixel_shift ≤ 1) the product ~67M fits in `int`. No overflow.

**Batch 2 (lines 600-1200):** `hls_slice_header` properly bounds `num_entry_point_offsets` (≤ bits_left and ≤ UINT16_MAX), and allocates `sh->entry_point_offset/offset/size` with `num_entry_point_offsets + 1` elements. The `val + 1` at line 1148 can wrap to 0 for `offset_len=32, val=UINT_MAX`, but this creates a zero-size chunk (not negative), causing no OOB.

**Batch 3-4 (lines 1200-2400):** `hls_pcm_sample` length calculation max is ~172K bits (safe for `int`). The `edge_emu_buffer` at `(MAX_PB_SIZE+7)*EDGE_EMU_BUFFER_STRIDE*2=11360` bytes is large enough for the cross-component prediction loop (`size*size` max 1024 `int16_t` = 2048 bytes). `ff_hevc_mpm_idx_decode` is bounded to {0,1,2} by construction, so `candidate[mpm_idx]` is always in-bounds.

**Batch 5-6 (lines 2400-3031):** `hls_slice_data_wpp` offset calculations: when `entry_point_offset[i]` is extremely large, `offset` exceeds `length`, and the check at line 2997 (`if (length < offset) return AVERROR_INVALIDDATA`) fires BEFORE `execute2` is called. Any corrupted `sh->size[i]` or `sh->offset[i]` values (from int64→int narrowing) are set in the loop but never consumed by `hls_decode_entry_wpp` because the function returns early. The `wpp_ctb_addresses_are_wrong` check at line 2942 provides additional protection.

**Batch 7 (lines 3031-4311):** Frame initialization and context management are clean. Thread-context copy properly re-uses reference-counted structures.

**Key structural properties that prevent vulnerabilities:**
- All `tab_ipm`/`tab_mvf`/`tab_slice_address` accesses are bounded by `width`/`height` dimensions validated in SPS parsing.
- HEVC constrains picture dimensions to multiples of `MinCbSizeY` (≥8), ensuring PU indices never overflow their floor-division-allocated arrays.
- The CABAC decoder reads are bounded by the NAL buffer established in `ff_h2645_packet_split`.
- All function-pointer array indices (`intra_pred[log2_trafo_size-2]`, `add_residual[...]`) are bounded by max transform sizes (log2≤5, index≤3).

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
