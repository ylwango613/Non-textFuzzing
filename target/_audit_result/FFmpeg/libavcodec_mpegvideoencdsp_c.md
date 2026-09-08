**Complete analysis of `mpegvideoencdsp.c` (308 lines):**

- **`denoise_dct_c`** / **`try_8x8basis_c`** / **`add_8x8basis_c`**: All operate on fixed-size 64-element stack arrays; loops are bounded by constant 64. No dynamic allocation. Clean.

- **`pix_sum_c`** / **`pix_norm1_c`**: Fixed 16×16 iteration. The `ff_square_tab` index pattern `sq = ff_square_tab + 256; sq[x & 0xff]` accesses indices 256–511, all within the 512-element table. `line_size` comes from `AVFrame->linesize[]`, computed at frame allocation time. Clean.

- **`draw_edges_lr`** / **`draw_edges_8_c`**: The `w` parameter is constrained to 4/8/16 via an `av_assert1` chain. The `width + w + w` memcpy size is an `int` expression, but in practice frame dimensions in all callers (Dirac decoder, Snow encoder) are derived from validated codec sequence headers (`s->seq.width`/`s->seq.height`) constrained well below overflow territory. The function is designed to operate on pre-allocated buffers with known border padding. Clean.

- **`shrink22`** / **`shrink44`** / **`shrink88`**: Pointer arithmetic steps use `src_wrap` (ptrdiff_t) from `AVFrame->linesize[]`; no dynamic allocation; no external-input-controlled buffer sizes. Clean.

- **`ff_mpegvideoencdsp_init`**: Only assigns function pointers; no allocation; no external input. Clean.

**Conclusion:** The file contains no dynamic memory allocation, no direct parsing of attacker-controlled byte streams, and all array accesses are bounded by either compile-time constants or codec-level validated frame parameters. No memory safety vulnerabilities are present in this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
