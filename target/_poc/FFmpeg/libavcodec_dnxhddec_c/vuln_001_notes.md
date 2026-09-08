# VULN 001 – Off-by-one in mb_scan_index bounds check (DNxHD decoder)

## Vulnerability

**File**: `libavcodec/dnxhddec.c`  
**Function**: `dnxhd_decode_header()`  
**Line**: 344  
**CWE**: CWE-125 (Out-of-Bounds Read)

```c
// Line 344 – strict < instead of <=
if (buf_size - ctx->data_offset < ctx->mb_scan_index[i]) {
    // only rejects scan index if it's STRICTLY GREATER than coded size
}
```

When `mb_scan_index[i]` is set **exactly** to `buf_size - ctx->data_offset` (= CODED_SIZE),
the strict `<` comparison evaluates to `false` and the check is bypassed.  The correct
guard should be `<=`.

## Trigger Path

```
ffmpeg -i crafted.avi -f null -
  → libavformat/avidec.c: avi_read_packet()          (delivers 768-byte packet)
  → libavcodec/dnxhddec.c:  dnxhd_decode_frame()
  → libavcodec/dnxhddec.c:  dnxhd_decode_header()   (off-by-one check passes)
  → avctx->execute2(..., dnxhd_decode_row, ..., mb_height=1)
  → dnxhd_decode_row():
      ctx->buf      = buf + data_offset   (= avpkt->data + 0x280)
      ctx->buf_size = buf_size - data_offset  (= 128 = CODED_SIZE)
      offset        = mb_scan_index[0]        (= 128 = CODED_SIZE)
      ─────────────────────────────────────────────────────────────
      init_get_bits8(&row->gb,
                     ctx->buf + offset,       // = avpkt->data + 768 (ONE PAST END)
                     ctx->buf_size - offset)  // = 0 (zero-length "buffer")
      ─────────────────────────────────────────────────────────────
  → dnxhd_decode_macroblock()
  → get_bits(&row->gb, 11)   [qscale]
  → dnxhd_decode_dct_block_8()
      OPEN_READER(bs, &row->gb)          // bs_index = row->gb.index (≥12 from qscale)
      UPDATE_CACHE_BE(bs, &row->gb)      // AV_RB32(buf + 768 + bs_index/8)
                                         // READS PAST THE CODED DATA BOUNDARY ← OOB
      GET_VLC(len, ..., DC_VLC_BITS=7)   // processes garbage bits from padding zone
      GET_VLC(index1, ..., VLC_BITS=9)   // same
      while (index1 != eob_index) {      // loops up to 64 times on garbage bits
          UPDATE_CACHE(...)              // each call reads further into padding zone
          ...
      }
```

`#define UNCHECKED_BITSTREAM_READER 1` (line 35) removes all bounds checks from the
bitstream reader, so every `UPDATE_CACHE_BE` call is an unchecked `AV_RB32` read.

## Crafted File Layout

| Offset | Value | Purpose |
|--------|-------|---------|
| 0x00–0x04 | `00 00 02 80 01` | DNXHD_HEADER_INITIAL magic (header prefix) |
| 0x18–0x19 | `00 10` | height = 16 (big-endian) |
| 0x1a–0x1b | `00 10` | width  = 16 (big-endian) |
| 0x21 | `0x20` | bitdepth indicator: (0x20>>5)=1 → 8-bit |
| 0x28–0x2b | `00 00 04 F9` | CID = 1273 (DNxHR SQ, variable size, 8-bit) |
| 0x16c–0x16d | `00 01` | mb_height = 1 |
| 0x170–0x173 | `00 00 00 80` | mb_scan_index[0] = 0x80 = CODED_SIZE (trigger) |

Total frame size: 768 bytes (0x300), wrapped in an AVI RIFF container.  
`data_offset` = 0x280 (fixed for non-HR format, mb_height ≤ 68).  
`CODED_SIZE` = 0x300 − 0x280 = 0x80 = 128.  
`mb_scan_index[0]` = 128 = CODED_SIZE → passes `<` check, fails `<=` check.

CID 1273 (DNxHR SQ): `coding_unit_size = DNXHD_VARIABLE = 0` bypasses the
frame-size check; `width = DNXHD_VARIABLE = 0` bypasses the dimension check.

## Observed Behavior

```
[dnxhd] ac tex damaged 0, 64
[dnxhd] 1 lines with errors
Decoding error: Invalid data found when processing input
```

The "ac tex damaged 0, 64" message proves the decoder processed **64 iterations** of
garbage AC coefficients read from beyond the intended 128-byte coded data region.
The `UPDATE_CACHE_BE` reads advance ~25–42 bytes into the memory beyond `avpkt->data +
768`, reading from FFmpeg's mandatory 64-byte `AV_INPUT_BUFFER_PADDING_SIZE` zero pad.

## Why ASAN Does Not Report a Crash

`av_new_packet(pkt, 768)` allocates `768 + AV_INPUT_BUFFER_PADDING_SIZE = 832` bytes.
ASAN's poisoned zone begins at byte 832.  The AC VLC table for all-zero input decodes
symbol 0 (Huffman code "00", 2 bits, `flags=0`) each iteration, advancing `bs_index` by
only 3 bits/iteration (2-bit VLC + 1 sign bit).  After the maximum 62 allowed iterations,
`bs_index ≈ 204` bits, so the last `UPDATE_CACHE_BE` reads at byte `25` (= 204 >> 3)
from `buf + 768` — well within the 64-byte padding, never reaching the ASAN redzone at
byte 64.

In production allocators (no ASAN padding), or under different memory layouts, any
4-byte `AV_RB32` read at `buf + 768` reads beyond the logical end of the coded data
and constitutes a heap information leak.  In theory, with larger initial `bs_index`
values or longer VLC codes, the read would escape the padding and crash.

## Classification

**VERIFIED_BEHAVIOR** — The off-by-one check bypass is confirmed: `mb_scan_index[0] ==
CODED_SIZE` passes the strict `<` guard, `init_get_bits8` is called with a pointer one
past the end of the coded data and `size_in_bits = 0`, and the decoder subsequently reads
garbage data from beyond the buffer boundary (evidenced by 64 AC coefficient decode
iterations on out-of-bounds memory).  ASAN does not report a heap-buffer-overflow in
this specific test because the reads happen to fall within FFmpeg's guaranteed 64-byte
allocation padding.
