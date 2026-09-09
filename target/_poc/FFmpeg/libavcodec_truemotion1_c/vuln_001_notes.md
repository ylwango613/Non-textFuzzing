# VULN 001 – TrueMotion1 interframe mb_change_bits heap-buffer-overflow

## File
`FFmpeg/libavcodec/truemotion1.c`

## Root cause
`truemotion1_decode_header()` (line ~449) sets:

```c
s->mb_change_bits = s->buf + header.header_size;
if (s->flags & FLAG_KEYFRAME) {
    // size check present
    if (s->avctx->width * s->avctx->height / 2048 + header.header_size > s->size)
        return AVERROR_INVALIDDATA;
} else {
    // NO size check for interframe!
    s->index_stream = s->mb_change_bits +
        (s->mb_change_bits_row_size * (s->avctx->height >> 2));
}
```

For a large-width interframe, `mb_change_bits_row_size` is huge.  The region
`[s->buf + header_size, s->buf + header_size + mb_change_bits_row_size * (height/4))`
is never bounds-checked, but is accessed byte-by-byte in `truemotion1_decode_16bit()`.

## Packet craft
- `buf[0] = 0x12`  →  `header_size = 16`  (passes `buf[0] >= 0x10` check)
- XOR-unscrambled header fields:
  - compression = 2 (ALGO_RGB16H, triggers `truemotion1_decode_16bit`)
  - vectable = 1, deltaset = 0 (valid)
  - ysize = 4 (multiple of 4, small)
  - xsize = 65534 (even, large)
  - version = 2, header_type = 2, flags = FLAG_INTERFRAME (no keyframe)
- Total packet = 17 bytes (just enough to pass `header_size + 1 <= size`)

## OOB math
```
mb_change_bits_row_size = ((65534 >> 2) + 7) >> 3 = 2048 bytes/row
rows needed             = height >> 2 = 4 >> 2 = 1
mb_change_bits needed   = 2048 bytes
available after header  = 17 - 16 = 1 byte
OOB by 2047 bytes
```

## Trigger path
`ffmpeg -i crafted.avi -f null -`
→ AVI demuxer → `truemotion1_decode_frame()`
→ `truemotion1_decode_header()` [interframe, no size check]
→ `truemotion1_decode_16bit()` → reads `mb_change_bits[0..2047]` OOB

## Expected crash
ASAN: heap-buffer-overflow (read) in `truemotion1_decode_16bit` at the
`mb_change_byte = mb_change_bits[mb_change_index++]` line.
