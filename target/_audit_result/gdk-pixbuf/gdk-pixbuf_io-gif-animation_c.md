I've now read the full `io-gif-animation.c` (554 lines), the complete `io-gif.c` (all key sections), `gdk-pixbuf.c` implementations of `gdk_pixbuf_new`, `gdk_pixbuf_new_subpixbuf`, `gdk_pixbuf_copy_area`, and the struct definitions. Let me summarize the analysis of each concern:

**Group 1 – compositing geometry (io-gif-animation.c:350-351, 406-407)**
`clipped_width = MIN(gif_anim->width - f->x_offset, …)` can be negative if x_offset > width, but every consumer is guarded by `if (clipped_width > 0 && clipped_height > 0)`.

**Group 2 – gdk_pixbuf_new_subpixbuf calls (lines 429-433, 472-477)**
`gdk_pixbuf_new_subpixbuf` carries `g_return_val_if_fail(src_x + width <= src_pixbuf->width)` — out-of-bounds returns NULL, not memory corruption.

**Group 3 – gdk_pixbuf_copy_area calls (lines 454-460)**
`gdk_pixbuf_copy_area` carries explicit `g_return_if_fail` bounds checks for both source and destination rectangles; any violation silently returns.

**Group 4 – composited pixbuf allocation (line 369-371)**
`gdk_pixbuf_new(…, gif_anim->width, gif_anim->height)` uses `g_try_malloc_n(height, rowstride)` with an inline rowstride overflow check — returns NULL on OOM, code checks NULL at line 373.

**Group 5 – LZW stack overflow**
`CHECK_LZW_SP()` macro guards every push to `lzw_stack[(1<<12)*2+1]`.

**Group 6 – LZW table OOB access**
`if (code >= (1 << MAX_LZW_BITS)) return -2` check before every `lzw_table` read; table dimension exactly `(1 << MAX_LZW_BITS)`.

**Group 7 – block_buf[-2/-1] read at code_last_byte=0 (io-gif.c:509-510)**
On the very first `gif_lzw_fill_buffer` call, `code_last_byte=0` causes `block_buf[-2]` and `block_buf[-1]` reads (into fields/padding before the array in the struct). However: (a) the values are immediately overwritten by `get_data_block`; (b) `get_code` starts extracting bits at `code_curbit=16` (byte 2 onwards), so bytes 0-1 are never read. Inert read from same struct, no exploitable impact.

**Group 8 – gif_fill_in_pixels stride mismatch (io-gif.c:733)**
The non-transparent branch uses `draw_xpos * 3` offset while the pixbuf has 4 bytes/pixel; writes within bounds (`xpos * 3 < xpos * 4 ≤ rowstride`) but to wrong position — visual glitch only, no OOB.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
