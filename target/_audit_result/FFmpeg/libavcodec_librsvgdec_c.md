After thorough analysis of `librsvgdec.c` (175 lines) and the full call chain, here is my conclusion:

The file is a thin wrapper around librsvg/cairo. Key observations:

1. **Dimension extraction (lines 63–69)**: `viewport.width/height` are `gdouble`; cast to `int` via `(int)viewport.width` is UB for out-of-range values, but the result is passed immediately to `ff_set_dimensions` → `av_image_check_size2`, which rejects negative values (treated as large `unsigned int` > `INT32_MAX`), zero, or stride-overflow dimensions. On invalid input `ff_set_dimensions` returns `AVERROR(EINVAL)` and the caller does `goto end` — no allocation proceeds.

2. **Division by zero (lines 78–80)**: `viewport.height` or `unscaled_dimensions.height` could be 0.0/0; floating-point division by zero yields ±infinity, propagated through `lrintf`. Any resulting bad `dimensions.width/height` is still caught by `av_image_check_size2` before any buffer is allocated.

3. **Cairo surface / frame buffer consistency (lines 101–103)**: The cairo surface is always created using `frame->width` and `frame->height` (from the validated, allocated frame), so the surface dimensions are internally consistent with the allocated buffer. librsvg clips rendering to the surface bounds.

4. **SVG parsing (line 55)**: `rsvg_handle_new_from_data(pkt->data, pkt->size, &error)` — any parsing vulnerabilities are in librsvg itself, outside FFmpeg's scope.

The FFmpeg wrapper code contains no exploitable memory-safety vulnerability on its own; the downstream validation in `av_image_check_size2` guards all allocation paths.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
