`bytestream2_seek` clips the offset to `[0, buffer_end - buffer_start]` (line 227), so over-large offsets never produce a past-end pointer — they land at the buffer end, `bytes_left` becomes 0, and all subsequent size checks reject the frame.

**Complete analysis summary across all code paths:**

- **`lzss_decompress`**: Output bounded by `dst_size` param; back-ref `oi < offset` check prevents underflow read; `count` (max 16) * 2 never overflows int.
- **`tileindex_data`** allocation = `tiles_w*8 * tiles_h*8` bytes; decode_tiledata writes `nb_tiles*64 ≤ tiles_w*tiles_h*64` bytes — within bounds.
- **`palmapindex_data`** allocation = `tiles_w*tiles_h`; decode_palmapdata writes exactly `tiles_h*tiles_w` entries — within bounds.
- **Palette**: `nb_pal ≤ 4` (checked line 328); decode_palette reads exactly 18 bytes (checked line 72); pixel values capped at `3*16 + 15 = 63 < 256`.
- **nb_tiles** from untrusted packet capped by `tiles_w*tiles_h` check (line 354).
- **`s->uncompressed`** (65536 bytes): all three write paths (`raw`, `lzss`, `left`) guard with `sizeof(s->uncompressed) - offset < size` before writing; `lzss_decompress` dst_size = remaining space.
- **Tilemap index** in `decode_index_tilemap`: `av_clip((tilemap & 511) - 1, 0, nb_tiles-1)` always in-range.
- **`tilemapdata_offset` / `tiledata_offset`** may be large, but `bytestream2_seek` clips to buffer end and the subsequent `bytes_left < size` check returns AVERROR_INVALIDDATA.
- **Integer products**: `tiles_w`, `tiles_h` are `uint8_t` (0-255); max products 65025 and 4,161,600 fit comfortably in `int`.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
