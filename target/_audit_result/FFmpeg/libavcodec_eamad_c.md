I now have all the critical data needed. Key finding from `utils.c` lines 155-248: `AV_PIX_FMT_YUV420P` falls through a long switch arm that terminates with `h_align = 16 * 2 = 32` and `w_align = 16` (line 244-245). This means frames are allocated with height rounded up to the nearest 32 pixels, not 2 pixels.

Let me verify the critical arithmetic:

**Frame allocation (get_buffer.c):**
- For height=17: `FFALIGN(17, 32) = 32` → Y plane has 32 rows, Cb/Cr each have 16 rows
- Pool size = `size[i] + 16 + STRIDE_ALIGN - 1` (≈ 79 bytes of trailing pad, not extra rows)

**Decoder access pattern for mb_y_max=1 (height 17–31):**
- Luma (j=3): writes rows 16–23 → allocated 32 rows → all within bounds ✓
- Chroma (mb_y=1): writes rows 8–15 → allocated 16 chroma rows → all within bounds ✓

The h_align=32 allocation exactly matches the 16-pixel macroblock stride, so the write OOB I was investigating is fully mitigated by the allocator.

**Review of remaining patterns:**

1. **comp_block() bounds check math**: `offset < (height - 7)*linesize - 7` → max access `< height*linesize`. Correct given h_align=32 allocation.
2. **Motion vector range**: `decode_motion()` returns [-16, 16]. Negative → unsigned wrap → caught by `offset >= threshold`. Correct.
3. **bitstream_buf allocation**: `av_fast_padded_malloc(size + AV_INPUT_BUFFER_PADDING_SIZE)` then `bswap16_buf` writes ≤ size bytes. Safe.
4. **Width/height validation**: `>= 16` check prevents degenerate dimensions.
5. **VLC decode**: `i > 63` check prevents OOB into `block[j]` and `scantable[i]`.
6. **Packet size pre-check**: `(width * (int64_t)height)/2048*7 > bytes_left` guards `ff_set_dimensions`.

No memory safety vulnerabilities were confirmed in this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
