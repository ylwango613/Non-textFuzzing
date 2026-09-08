After a complete multi-pass audit of `mscc.c` (280 lines) and all relevant call-chain context, here is my analysis:

**Findings checked:**

1. **`decode_init` stride integer overflow** (`avctx->width * avctx->bits_per_coded_sample`): Would overflow int32 for widths > ~67M pixels, but `ff_set_dimensions` → `av_image_check_size2` is called (in `avcodec.c` line 234-236) before `decode_init`, enforcing the constraint `(8*w + 1024) * (h + 128) < INT_MAX`. This makes the actual stride formula in `decode_init` safe.

2. **`decomp_size = 2 * avctx->height * stride` overflow**: For bpc=32 this equals `8*w*h`. The `av_image_check_size2` constraint implies `8*w*h < INT_MAX`, so this stays within int32 for all validated dimensions.

3. **OOB write to `uncomp_buf` via RLE decoder**: `rle_uncompress` has explicit checks at lines 57 and 108 (`bytestream2_get_bytes_left_p < run/copy * bpp`), and the underlying `bytestream2_put_*` API checks EOF before each write. No OOB write path.

4. **`bytestream2_seek_p` integer overflow** (lines 98, 106): `y * avctx->width * s->bpp` accumulates via `copy==2` and can overflow int32, but `bytestream2_seek_p` uses `av_clip(offset, 0, buffer_end - buffer_start)` (bytestream.h line 258), clamping any negative or overflowed value to a valid range.

5. **OOB read in `memcpy` loop** (lines 203-206): For non-overflowing valid dimensions, `s->bpp * j * avctx->width` at `j = height-1` gives exactly `uncomp_size` bytes, which is within the allocated buffer.

6. **Uninitialized `fill` variable** (line 53): Latent UB when `bits_per_coded_sample` doesn't match switch cases, but `decode_init` rejects unsupported bit depths before `decode_frame` is ever called.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
