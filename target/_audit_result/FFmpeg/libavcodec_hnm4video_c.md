Now I have the complete picture. Let me verify the key dimension constraint from `av_image_check_size2` line 301:

`stride*(h + 128ULL) >= INT_MAX` where stride = `8LL*w + 1024` — this limit constrains `w*h` to well below `INT_MAX`, which prevents integer overflow in `hnm->width * hnm->height` multiplications used throughout the decoder.

Key findings from the full analysis:

1. **Allocation (lines 474–476)**: `av_mallocz(avctx->width * avctx->height)` — the `av_image_check_size` stride check (`(8*w + 1024)*(h + 128) < INT_MAX`) ensures `w*h < INT_MAX`, so the `int*int` product never overflows and allocations are correctly sized.

2. **`hnm_update_palette`**: `writeoffset` is `uint8_t`, palette has 256 entries — wrapping stays within bounds. Bytestream2 reads are safe.

3. **`decode_interframe_v4`**: Bounds checks at lines 81, 103, 106, 167, 193, 209, 212, 215, 222–230 correctly gate all `current[]`/`previous[]` accesses. Negative `offset` is caught by the `offset < 0` / `offset < (2*width-1)` checks. The backward loop minimum-offset pre-check prevents underflow during iteration.

4. **`decode_interframe_v4a`**: Bounds checks at lines 297, 309, 329, 332 correctly guard all accesses. `uint32_t` writeoffset and offset cannot practically overflow given the dimension constraints.

5. **`postprocess_current_frame`** and **`copy_processed_frame`**: pointer arithmetic `y * width` is correctly bounded because `height` and `width` are restricted to values where their product does not overflow `int`.

6. **No unsafe integer multiplications, no unchecked chunk-size copies, no stack buffer overflows** were identified.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
