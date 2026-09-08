# VULN 001 - PoC Notes: ipu_decode_frame Heap OOB Write

## Summary

`ipu_decode_frame()` in `libavcodec/mpeg12dec.c` performs a heap out-of-bounds write when the video height is not a multiple of 16. The IPU demuxer (`libavformat/ipudec.c`) reads the height directly from the file header with no alignment validation.

## Trigger Path

```
ffmpeg -i crafted.ipu -f null -
  -> avformat_open_input()
  -> ipu_read_probe()         # checks magic 'ipum' and non-zero fields
  -> ipu_read_header()        # reads height=17 from bytes 10-11 (LE16)
  -> ipu_decode_frame()       # called per frame packet
       -> ff_get_buffer()     # allocates frame for exactly 17 luma rows
       -> outer y-loop: y=0, y=16
       -> for y=16, x=0:
            idct_put(frame->data[0] + (16+8)*linesize + 0)  # row 24, OOB!
            idct_put(frame->data[0] + (16+8)*linesize + 8)  # row 24, OOB!
```

## Root Cause

- `ipu_read_header()` (ipudec.c:61): `st->codecpar->height = avio_rl16(pb)` — no `FFALIGN(h, 16)`.
- `ipu_decode_frame()` (mpeg12dec.c:2804): `for (int y = 0; y < avctx->height; y += 16)` — iterates y=0 and y=16 when height=17.
- `ff_get_buffer()` allocates a frame buffer for exactly `avctx->height=17` rows.
- For y=16: `idct_put(frame->data[0] + (y+8)*linesize + x)` writes 8 rows starting at row 24, which is 7 rows past the end of the allocated 17-row buffer.

## Bitstream Construction

The crafted `.ipu` file contains:

### Header (16 bytes)
| Offset | Value | Description |
|--------|-------|-------------|
| 0-3    | `ipum` | Magic (big-endian ASCII) |
| 4-7    | `01 00 00 00` | Non-zero field (probe requirement) |
| 8-9    | `10 00` | Width = 16 (1 macroblock column) |
| 10-11  | `11 00` | Height = **17** (non-multiple of 16!) |
| 12-15  | `01 00 00 00` | Frame count = 1 |

### Packet (13 bytes)
Flags byte 0x80 selects MPEG-1 intra coding (`ff_mpeg1_decode_block_intra`).

The bitstream encodes 2 macroblocks (y=0 and y=16) with zero-valued DCT blocks:
- **Luma DC size=0**: VLC code `100` (3 bits, diff=0)
- **Chroma DC size=0**: VLC code `00` (2 bits, diff=0)  
- **AC end-of-block**: `10` (2 bits; detected via cache check, consumed by `LAST_SKIP_BITS` at `end:` label)

After all MBs: 5 alignment bits + 4 zero bytes (32 bits) to satisfy the `get_bits_left(gb) == 32` check.

## Expected ASAN Output

```
ASAN: heap-buffer-overflow on address ...
WRITE of size 8 at ...
  #0 ... ipu_decode_frame (mpeg12dec.c:2847)
```

The write happens at `idct_put(frame->data[0] + (y+8)*linesize + x)` for y=16, writing row 24 of a 17-row buffer.

## Variations

If the initial 13-byte packet does not trigger a clean ASAN report, the generator can be modified to use:
- Different height values: 1, 3, 5, 8, 15 (all non-multiples of 16)
- Width=16 with height=33 for 3 MB rows
- Any odd height will trigger the OOB on the last MB row's lower 8-row block
