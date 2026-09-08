# VULN-001: lead_decode_frame YUV444P heap OOB write

## Vulnerability summary

**CWE-787 Out-of-bounds Write** in `lead_decode_frame()` (`libavcodec/leaddec.c`, lines 286-302).

In the YUV444P branch the outer loop iterates:

```c
for (int j = 0; j < (avctx->height + 7) / fields / 8; j++)
```

With `height=9` and `fields=1` this gives `j < (9+7)/8 = 2`, so j=0 and j=1.
For j=1 the destination pointer is:

```c
frame->data[plane] + (f + 8*j*fields) * frame->linesize[plane] + 8*i
                   = frame->data[plane] + 8 * frame->linesize[plane]   // row 8
```

`idct_put()` then writes 8 rows (rows 8 through 15).  The frame buffer for
YUV444P is allocated with exactly `height=9` rows (alignment factor = 1).
Only row 8 is within bounds; rows 9-15 (7 rows * linesize bytes each) are
written past the end of the allocation, constituting a heap OOB write.

## Trigger conditions

| Field | Value |
|-------|-------|
| Container | AVI (RIFF/AVI) |
| Codec FourCC | `LEAD` |
| `biCompression` | `LEAD` |
| Width | 16 |
| Height | **9** (not a multiple of 8) |
| Frame byte[4:6] (format) | `0x2000` (YUV444P) |
| Frame byte[6:8] (quality) | 50 |

## PoC approach

`vuln_001_gen.py` builds a minimal but well-formed AVI file:

1. **RIFF/AVI container** with one video stream, `fccHandler=LEAD`,
   `biCompression=LEAD`, `biWidth=16`, `biHeight=9`.
2. **extradata**: the `strf` chunk is padded to 60 bytes (40-byte
   BITMAPINFOHEADER + 20 extra zero bytes) so `avctx->extradata_size >= 20`
   passes the init guard.
3. **Frame payload** (40 bytes):
   - Bytes 0-3: zero padding
   - Bytes 4-5: `0x00 0x20` → `AV_RL16 = 0x2000` (selects YUV444P branch)
   - Bytes 6-7: `0x32 0x00` → quality q = 50
   - Bytes 8-39: `0x80` × 32 — each byte XOR'd with 0x80 inside the decoder
     becomes `0x00`, producing an all-zero bitstream.  An all-zero stream
     decodes as a valid sequence of (DC-category-0, AC-EOB) pairs (each
     costing 4 bits), because the shortest luma/chroma DC code is `"00"` (2
     bits) and the shortest AC EOB code is also `"00"` (2 bits).

The size check inside the decoder:
```
(avpkt->size - 8) * 8  >=  ceil(16/8) * ceil(9/8) * 3 * 4
         (40-8)*8=256  >=  2 * 2 * 3 * 4 = 48   ✓
```

4. `vuln_001_run.sh` runs ffmpeg with `ASAN_OPTIONS` that capture any
   heap-buffer-overflow report to `asan_001.log.*`.

## Expected behavior

With ASAN enabled, ffmpeg should report a **heap-buffer-overflow WRITE** during
the j=1 decode iteration, emanating from `idct_put` called inside
`decode_block` inside `lead_decode_frame`.

Without ASAN the write silently corrupts memory adjacent to the frame buffer,
potentially leading to use-after-free or other downstream memory corruption.

## Trigger path

```
ffmpeg -i vuln_001_input.avi -f null -
  → avformat_open_input()
  → avi_read_header()         (reads strf, sets codec params)
  → avi_read_packet()         (delivers '00dc' chunk as AVPacket)
  → avcodec_send_packet()
  → lead_decode_frame()
    → ff_get_buffer()         (allocates frame with height=9 rows)
    → decode_block() j=1      (dst = frame->data + 8*linesize → past buffer)
    → idct_put()              ← OOB WRITE rows 9-15
```
