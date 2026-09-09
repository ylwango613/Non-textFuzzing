Now I have complete picture. Let me verify the `av_fast_malloc` behavior when `min_size <= *size` (reuse path) to confirm the overflow scenario:

- Line 715: `max_slice_size += 4*avctx->width` — if this overflows `int` (requires width > ~536M), the negative int is passed to `size_t min_size` → enormous value → `min_size > max_size (UINT_MAX)` → `av_freep(ptr); *size = 0` → `c->slice_bits = NULL` → checked at line 721 → returns ENOMEM. Not a corruption path.

- Line 1060: `av_calloc(avctx->width + 8, ...)` — signed overflow UB, but `av_calloc` applies `av_size_mult` which catches the wrapped huge `nmemb` → returns NULL → checked. Not corruption.

- Slice size / memset safety (lines 204, 349): `slice_size` values in `decode_plane`/`decode_plane10` read from the same bytes that `decode_frame` already validated for monotonicity and buffer-bounds. `slice_size ≤ max_slice_size`. The `memset(c->slice_bits + slice_size, 0, 64)` and `bswap_buf` remain within the `max_slice_size + 64` allocation. No OOB.

- Pack stream arrays `[4][256]`: `c->planes ≤ 4`, `c->slices ≤ 256` (extradata byte + 1, or frame_info byte + 1). `j` in `[0, c->slices-1]` → `[0, 255]`. Exactly within bounds.

- `get_vlc_multi` writes in `READ_PLANE`: group size is 2 (passed to `ff_vlc_init_multi_from_lengths`), so max 2 symbols per call, bounded by `width - end`. No OOB write.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
