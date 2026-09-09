Having completed a thorough analysis:

**`getv()` analysis**: The multi-byte VLC decoder has no loop limit, but `bytestream2_get_byte` returns 0 at buffer exhaustion (0x80 bit clear → loop terminates). Integer overflow in `v` is possible, but when the overflowed value is assigned to `int width/height` and passed to `ff_set_dimensions`, the `av_image_check_size2` check catches any value > INT32_MAX or ≤ 0 and returns AVERROR(EINVAL).

**`height * ((width + 7) / 8)` overflow analysis**: The constraint from `av_image_check_size2` with `AV_PIX_FMT_NONE` effectively enforces `8*W*H < INT_MAX`, which means `H * ceil(W/8) ≤ HW/8 + H < ~35M`, well below INT_MAX. No signed integer overflow possible in line 73.

**`readbits()` OOB write analysis**: For `AV_PIX_FMT_MONOBLACK`, linesize is always ≥ `(width+7)/8`, so `wpad ≤ linesize`. The `memcpy` copies at most `FFMIN(wpad, size)` bytes per row, not exceeding `linesize`. Loop iterates at most `height` times. No OOB write.

**`bytestream2_get_buffer` (line 73)**: Only reached when `linesize == (width+7)/8`, writing exactly `height * linesize` bytes = exactly the allocated plane size.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
