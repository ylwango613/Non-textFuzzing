# VULN 002 – truemotion1_decode_24bit() missing keyframe guard

## Bug location
`libavcodec/truemotion1.c`, function `truemotion1_decode_24bit()`, line 783.

## Root cause
The 24-bit TrueMotion1 decoder unconditionally reads the `mb_change_bits`
array at the start of every row:

```c
// line 782-783
mb_change_index = 0;
mb_change_byte = mb_change_bits[mb_change_index++];   // NO keyframe guard
```

The 16-bit decoder (`truemotion1_decode_16bit`, line 656) correctly guards
this read:

```c
// 16-bit – safe
if (!keyframe)
    mb_change_byte = mb_change_bits[mb_change_index++];
```

## Why it matters for keyframes
For a keyframe, `truemotion1_decode_header()` (lines 449–453) sets:

```c
s->mb_change_bits = s->buf + header.header_size;
if (s->flags & FLAG_KEYFRAME) {
    // no change bits; pointer aliases the index stream
    s->index_stream = s->mb_change_bits;
    ...
}
```

`mb_change_bits` and `index_stream` point to the **same** byte.
Every call to line 783 consumes one byte of what is actually the index
stream, and after every 4 rows the pointer advances by
`mb_change_bits_row_size` (line 870):

```c
if (((y + 1) & 3) == 0)
    mb_change_bits += s->mb_change_bits_row_size;
```

With a short packet the advancing pointer would walk past the end of the
allocated buffer.  In practice, the `GET_NEXT_INDEX` macro (line 532–539)
exhausts the index stream before the pointer reaches the ASAN red-zone,
triggering the "help! truemotion1 decoder went out of bounds" early-return
rather than a hard ASAN crash.  This confirms the missing guard at line 783
corrupts decoder state: index bytes are silently consumed as change-bit bytes,
causing premature index-stream exhaustion.

## Packet crafting
- **buf[0] = 0x11** → `header_size = ((0x11>>5)|(0x11<<3)&0xFF) & 0x7f = 8`
- XOR chain encodes: `compression=10` (ALGO_RGB24H), `vectable=1`,
  `ysize=4` (height), `xsize=4` (raw; `avctx_width = 4>>1 = 2`)
- `version=0` (from uninitialized `header_buffer[9]=0`) → `FLAG_KEYFRAME`
- Packet size = 9 bytes (header_size=8 + 1 data byte)

All validity checks pass:
- `buf[0] >= 0x10` ✓
- `header_size + 1 = 9 <= s->size = 9` ✓
- `compression=10 < 17` ✓
- `vectable=1 ∈ [1,3]` ✓
- `avctx_width=2` (even) ✓
- `height=4` (multiple of 4) ✓
- `avctx_width*height/2048 + header_size = 0+8 = 8 <= 9` ✓

## Observed behavior
`ffmpeg` prints:
```
[truemotion1] help! truemotion1 decoder went out of bounds
```
twice (once during `avformat_find_stream_info` and once during decode).
This message originates from `GET_NEXT_INDEX` (line 535), which fires
prematurely because the bug at line 783 consumed index bytes as change-bit
data.

## Why no ASAN crash (limitation of this PoC)
`AV_INPUT_BUFFER_PADDING_SIZE = 64` bytes.  The allocated packet buffer is
`packet_size + 64 = 73` bytes.  With `mb_change_bits_row_size = 1`, the
pointer only advances 1 byte past `s->size` after y=3, landing within the
64-byte ASAN-clear padding region.  To reach the ASAN red-zone, the pointer
would need to advance 65+ bytes, requiring height ≥ 260 groups × 4 rows.
However, the `GET_NEXT_INDEX` early-return fires first, preventing the decoder
from completing those rows.  This is a structural limitation: the index bytes
required to survive N groups of 4 rows always exceed the `mb_change_bits`
advancement by the same N, making an ASAN-detectable OOB unreachable without
disabling the `GET_NEXT_INDEX` bounds check.

## Status
`VERIFIED_BEHAVIOR` — the bug code path is confirmed active; the missing guard
on line 783 is demonstrably hit, causing premature index-stream exhaustion and
an observable "out of bounds" message.
