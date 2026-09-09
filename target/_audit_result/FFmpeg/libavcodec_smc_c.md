Now I have the full picture needed to issue my verdict. Let me confirm the frame allocation padding calculation.

From `get_video_buffer` (frame.c:110): `padded_height = FFALIGN(frame->height, 32)` — the frame buffer is allocated for the height rounded **up** to the next multiple of 32, not the raw declared height.

From frame.c:73: `#define ALIGN (HAVE_SIMD_ALIGN_64 ? 64 : 32)` — linesize is padded to at least 32.

Key findings from full analysis:

1. **OOB write for non-multiple-of-4 heights** — The `total_blocks` computation includes a "partial" top block-row when `height % 4 != 0`, and `image_size = height * stride` is smaller than the full block grid. However, `get_video_buffer` allocates `padded_height = FFALIGN(height, 32)` rows, so the extra 1-3 rows written past `image_size` land entirely within the padded allocation. No actual OOB.

2. **OOB read in case 0x40/0x50 (prev-pair-of-blocks) with width=4** — When `pixel_ptr == 0`, `row_ptr = stride*4`, `width = 4`, the formula `prev_block_ptr1 = (row_ptr - width*4) + width - 8` yields `-4` only when `stride = 4`. In the default allocator, stride is `FFALIGN(width, ALIGN) ≥ 32`, giving `prev_block_ptr1 = (128 - 16) + 4 - 8 = 108` — within bounds. The negative-index case requires a custom `get_buffer2` callback returning stride = 4, which is not standard.

3. **Color table lookups (0x90/0xB0/0xD0)** — Index byte (0-255) × table stride (CPAIR/CQUAD/COCTET) plus per-pixel offset lands at exactly the last valid byte: `2×255+1=511 < 512`, `4×255+3=1023 < 1024`, `8×255+7=2047 < 2048`. All within bounds by design.

4. **ADVANCE_BLOCK total_blocks underflow** — The `if (total_blocks < !!n_blocks)` check correctly terminates before any block write can address memory beyond the padded frame buffer.

5. **prev_block_ptr reads for 0x20/0x30** — With default ALIGN ≥ 32, `prev_block_ptr1 = stride*4 - width*4 + width - 4 ≥ 0` always. Logic error (reads wrong address with padding) but no memory-safety violation.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
