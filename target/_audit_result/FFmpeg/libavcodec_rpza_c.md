The analysis is now complete. Here is my conclusion after a thorough, multi-pass examination:

**Key findings from the analysis:**

1. **Height-not-multiple-of-4 concern**: The RPZA decoder computes `total_blocks = ceil(width/4) * ceil(height/4)` and writes into 4×4 pixel blocks via `ADVANCE_BLOCK()` which increments `row_ptr` by `stride*4` each block row. This would seem to write 3 extra rows beyond `height` when `height % 4 != 0`. However, `get_video_buffer()` (`libavutil/frame.c:110`) allocates `FFALIGN(frame->height, 32)` rows — rounding up to the nearest multiple of 32. This means the buffer always has at least 28 spare rows of padding at the bottom (since RPZA can only over-run by at most 3 rows). This completely mitigates the issue.

2. **Bytestream read bounds**: All `bytestream2_get_*u` fast-path calls in the decode loop are guarded by explicit `< N bytes` checks immediately before use (`line 195`, `line 215`). No OOB reads from the bitstream.

3. **`total_blocks` integer overflow**: For `width * height ≤ INT_MAX` (enforced by `av_image_check_size2` at `decode.c:1787`), `total_blocks ≤ INT_MAX/16`, which fits safely in `int32_t`.

4. **`row_ptr` integer overflow**: `row_ptr_max = stride * 4 * (ceil(height/4) - 1) ≈ width * (height - 4) = width*height - 4*width < INT_MAX` for all valid `width * height ≤ INT_MAX`. No signed overflow.

5. **`row_inc = stride - 4`**: For any valid non-zero width, the linesize is aligned to 32 bytes (stride ≥ 16 uint16_t), so `row_inc ≥ 12`. Never negative.

6. **`n_blocks * 4` overflow**: `n_blocks ≤ 32` (5-bit field + FFMIN guard), so `n_blocks * 4 ≤ 128`. Safe.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
