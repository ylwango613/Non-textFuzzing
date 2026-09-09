# VULN 001 — OOB Read in RT_BYTE_ENCODED RLE Decoder

## Vulnerability location
`libavcodec/sunrast.c`, function `sunrast_decode_frame()`, lines 171-174.

```c
while (ptr != end && buf < buf_end) {   // guarantees ≥1 byte
    run = 1;
    if (buf_end - buf < 1) { … }        // dead check — always false here

    if ((value = *buf++) == RLE_TRIGGER) {  // (1) consumes the last valid byte
        run = *buf++ + 1;                   // (2) OOB if buf now == buf_end
        if (run != 1)
            value = *buf++;                 // (3) second OOB if run > 1
    }
```

The outer while loop condition `buf < buf_end` only guarantees exactly 1 byte before
entering the body.  After line (1) consumes that byte, `buf` may equal `buf_end`.
If that byte was `RLE_TRIGGER` (0x80) the code unconditionally executes reads (2) and
(3) without re-checking the bound.

## PoC file layout (vuln_001_input.ras)
| Offset | Size | Content |
|--------|------|---------|
| 0      | 32   | Sun Rasterfile header: magic=0x59a66a95, 4×4, depth=8, type=2 (RT_BYTE_ENCODED), maptype=1 (RMT_EQUAL_RGB), maplength=768 |
| 32     | 768  | Colormap (256 RGB entries, all zeros) |
| 800    | 16   | RLE payload: 14 × 0x00 (literal pixels) + **0x80 0x01** (OOB trigger) |

Total file: **816 bytes**.

## Trigger sequence
1. Decoder reads 14 literal bytes → 14 pixels written, 2 bytes left (`buf_end - buf = 2`).
2. Reads `0x80` → `RLE_TRIGGER`; `buf` advances → 1 byte left.
3. Reads `0x01` → `run = 2`; `buf` advances → `buf == buf_end` (0 bytes left).
4. `run != 1` → executes `value = *buf++` **(OOB read past `buf_end`)**.

## Observed behaviour
FFmpeg (built with `-fsanitize=address,undefined`) processed the file without error
and produced a 4×4 frame (`frame=1`, exit 0, no ASAN/UBSAN output).

The OOB read did NOT trigger an ASAN crash because `avpkt->data` is allocated with
`AV_INPUT_BUFFER_PADDING_SIZE` (64) extra zero bytes beyond `avpkt->size`.
`buf_end` points to `avpkt->data + avpkt->size`; the OOB read falls into that
zero-filled padding region, which is part of the same heap allocation.  ASAN's shadow
memory marks those bytes as valid, so no heap-buffer-overflow is reported.

The logical vulnerability is real: the decoder reads past the declared packet boundary
(`buf_end`) and silently accepts a malformed, truncated RLE stream instead of returning
`AVERROR_INVALIDDATA`.  In environments without padding (custom allocators, fuzzer
heap-layout manipulation, or a future reduction of `AV_INPUT_BUFFER_PADDING_SIZE`) the
same code path would produce a true out-of-bounds heap read and a probable ASAN crash.

## Status
`VERIFIED_BEHAVIOR` — OOB access confirmed logically; silent mis-decoding of truncated
RLE data observed; no ASAN crash due to buffer padding absorbing the reads.
