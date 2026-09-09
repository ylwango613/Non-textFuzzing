Complete analysis done. Here is my full audit of all code paths:

**Read 1 (lines 1–255): Full file — single function group `decode_frame` + `decode_init` + `decode_close`**

Checked every arithmetic/allocation/bound for each `blocks` range:

1. **`blocks = 0`**: no loop iterations, no writes. Safe.
2. **`blocks 1–5`** (`else if (blocks)` branch): block headers read directly from packet via bytestream2 (returns 0 on underrun, never OOB). Overflow guard at lines 136–138 uses `bpp*(int64_t)w*h > INT_MAX`. The assignment `x += bpp*w*h` as plain int is safe because the guard proves the value ≤ INT_MAX before assigning. Frame write: `dst` bounded by `x+w ≤ width` and `y+h ≤ height` (lines 176–180). `avail_out = w*bpp` ≤ 262140 fits in `uInt`. First zlib stream uses `avail_out = sizeof(block_data) = 65536*8`; any overlong decompression returns Z_OK ≠ Z_STREAM_END → error.
3. **`blocks 6–65535`** (`blocks > 5` branch): `blocks*8` max = 524280 < sizeof(block_data) = 524288, so `bytestream2_init(&bgb, s->block_data, blocks*8)` is within bounds. Same overflow guard (lines 107–109). Main decode loop uses same w/h values from the same block_data bytes, same bounds checks.
4. **`y = avctx->height, h = 0`** edge: passes `y+h > avctx->height` check; `dst` points before frame buffer but inner loop runs 0 times → no actual memory access.
5. **Stale `block_data` bytes**: if zlib produces fewer bytes than `blocks*8`, stale bytes are read as block headers; bounds checks in main loop still gate all frame writes.
6. **`avail_in` computation**: `bytestream2_tell` is clamped to buffer end, so `avpkt->size - skip ≥ 0` always.

All arithmetic, allocation sizes, array index computations, and zlib output limits are properly bounded. No exploitable memory-safety path found.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
