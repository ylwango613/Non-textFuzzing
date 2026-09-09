I've now completed a thorough analysis of `rawenc.c` and its entire call chain. Here is my finding:

**Analysis summary:**

The file is 94 lines and implements a raw video encoder with two main functions.

**`raw_encode` (lines 49–82)** — the only function with non-trivial logic:

1. **Buffer size calculation (line 52):** `av_image_get_buffer_size` validates dimensions through `av_image_fill_linesizes` (`image_get_linesize` checks `max_step > INT_MAX / shifted_w`) and then validates total size with `sizes[i] > INT_MAX - ret`. This strictly bounds `pkt->size ≤ INT_MAX`.

2. **yuv2 loop (line 69):** `frame->height * frame->width * 2` — for YUYV422 with align=1, `pkt->size = width × 2 × height`. `av_image_get_buffer_size` only succeeds if this product fits in `int` (checked via 64-bit `ptrdiff_t` × `height` against `INT_MAX`). The loop bound therefore cannot overflow without `av_image_get_buffer_size` having already rejected the dimensions.

3. **b64a loop (line 75–78):** `8 * x` where `x < frame->height * frame->width`. For RGBA64BE, `pkt->size = width × 8 × height ≤ INT_MAX`, meaning `width × height ≤ 268,435,455`. Maximum `8 * x = 8 × 268,435,454 = 2,147,483,632`, which fits in `int` without overflow.

4. **`ff_get_encode_buffer` (encode.c:110):** provides an additional guard `size > INT_MAX - AV_INPUT_BUFFER_PADDING_SIZE`.

All integer paths through this file are protected by upstream validation before the loops are reached. No allocation, indexing, or size relationship is exploitable.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
