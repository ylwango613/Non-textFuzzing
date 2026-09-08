Analysis complete. Let me summarize the key findings from examining fraps.c (347 lines) in full detail:

**Group 1 — Offset validation & plane size checks (lines 203–215):**
The check at line 205 ensures `offs[i+1] - offs[i] > 1024` for planes 0 and 1, but `offs[3] - offs[2]` (last plane) has no lower bound beyond ≥ 1. However, when `offs[3] - offs[2] < 1024`, the `av_fast_padded_malloc` call at line 212 receives a huge underflowed `size_t` value. The `av_fast_padded_malloc` implementation (utils.c:56) has `if (min_size > SIZE_MAX - AV_INPUT_BUFFER_PADDING_SIZE)` guard, and even if that doesn't trigger (64-bit), the ~4GB allocation itself fails, setting `s->tmpbuf = NULL`, which is caught by `if (!s->tmpbuf) return AVERROR(ENOMEM)` at line 214. Path safely blocked.

**Group 2 — `bytestream_get_le32` unbounded reads (lines 99–101):**
Reads exactly 1024 bytes regardless of `size`. For planes 0/1 the size is > 1024 (validated). For plane 2 with size < 1024, the ENOMEM gate (above) prevents reaching `fraps2_decode_plane`.

**Group 3 — `bswap_buf` with negative count (lines 109–110):**
If `size` becomes negative after `size -= 1024`, `size >> 2` is a negative `int`. `bswap_buf` takes `int w` and the loop `for (i=0; i<w; i++)` does not execute for negative w. Safe.

**Group 4 — `init_get_bits8` negative size (lines 112–113):**
`init_get_bits8` explicitly checks `byte_size < 0` (get_bits.h:547) and returns AVERROR_INVALIDDATA, caught at line 112. Safe.

**Group 5 — `needed_size` integer overflow (lines 170–171, 179):**
`avctx->width * avctx->height` computed as `int * int` can theoretically overflow for large dimensions (e.g. 65536×65536 → 0), making `needed_size` very small and the size equality check passable. However, the subsequent `ff_thread_get_buffer` for such dimensions would require allocating multi-GB frames, which fails with ENOMEM, preventing the copy loops from executing.

**Group 6 — `UNCHECKED_BITSTREAM_READER` (line 37):**
The padding from `av_fast_padded_malloc`'s `AV_INPUT_BUFFER_PADDING_SIZE` zeroed suffix covers the unchecked bitreader's read-ahead. Overread is detected via `get_bits_left < 0` check (line 125). By design.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
