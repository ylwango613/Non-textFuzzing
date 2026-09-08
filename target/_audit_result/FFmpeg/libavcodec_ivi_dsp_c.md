After reading the full 848-line file and tracing all key call paths, I've completed the analysis:

**Summary of findings:**

1. **`ff_ivi_recompose53` / `ff_ivi_recompose_haar`**: Hardcode `num_bands = 4` and unconditionally access `plane->bands[0..3]`. However, both Indeo4 (`indeo4.c:190-193`) and Indeo5 (`indeo5.c:86-88`) enforce `luma_bands == 4` before setting `is_scalable`, so these functions are never reached when `num_bands < 4`. The OOB array access is blocked at the caller.

2. **Odd-height corner case**: The loop writes rows `y` and `y+1`, so an odd `plane->height` would write one row past the last valid row. However, FFmpeg's `ff_get_buffer` pads allocations with at least 16 extra rows via `avcodec_align_dimensions2`, so this write always lands in well-allocated padding and cannot corrupt adjacent heap data.

3. **Motion compensation bounds**: `ivi_mc` uses `av_assert0` for the primary reference bounds (always-on in FFmpeg), preceded by explicit `AVERROR_INVALIDDATA` checks in `ivi_decode_blocks` (`ivi.c:667-688`) that validate `mb->xpos + dmv_x + mb_size + cx <= pitch` and `mb->ypos + dmv_y + mb_size + cy <= aheight` before any `ivi_mc` call. The sub-block offsets (`blk_size` multiples within the MB) remain within the already-validated MB region.

4. **Stack buffers in transforms**: All fixed-size stack arrays (`tmp[64]`, `tmp[16]`, `tmp[size*size]`) are used with matching hard-coded access patterns. No overflow possible.

5. **MC halfpel `ref_buf[j+1]` access**: For `mc_type & 1` (horizontal halfpel), `ref_size = 1` is added to the bounds check in `ivi_mc`, correctly accounting for the one-past-end column read.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
