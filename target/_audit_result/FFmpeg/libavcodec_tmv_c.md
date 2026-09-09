I now have all the context needed for a complete analysis. Let me summarize the findings:

**Analysis summary of `libavcodec/tmv.c`:**

1. **Font array access** (`cga_font`): `font[ch * font_height + char_y]` where `ch` is a `uint8_t` (0-255), `font_height=8`, `char_y` ∈ 0-7. Max index = 255×8+7 = 2047. The font is `cga_font[2048]`. Exactly in-bounds.

2. **Size check** at line 50: `2*char_rows*char_cols`. `char_cols`/`char_rows` come from `avctx->width >> 3` / `avctx->height >> 3`. The demuxer bounds these via `avio_r8()` (single-byte reads, max 255 each). Max product: 2×255×255 = 130050 — no integer overflow.

3. **Frame pixel writes**: `dst + x*8` with `ff_draw_pc_font` writes exactly `char_cols*8` × `char_rows*8 = avctx->width × avctx->height` pixels — matches `ff_get_buffer` allocation.

4. **Palette write**: `memcpy(frame->data[1], ff_cga_palette, 64)` then `memset(frame->data[1]+64, 0, 960)` — totals exactly `AVPALETTE_SIZE = 1024` bytes. In-bounds.

5. **Packet source read**: The loop consumes exactly `2 * char_rows * char_cols` bytes from `src`, which the guard at line 50 guarantees is available.

6. **Zero-dimension edge case**: The demuxer rejects `video_chunk_size == 0` (line 107-110), preventing degenerate 0-dimension frames.

The demuxer (`libavformat/tmv.c`) enforces that `char_cols` and `char_rows` are single-byte values (max 255), and all arithmetic in the decoder respects these bounds. No exploitable integer overflows, heap under-allocations, or OOB accesses were found.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
