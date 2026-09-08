# VULN-001 — mpc7 lastframelen Heap OOB Read: Analysis & PoC Notes

## Vulnerability Summary

- **File**: `libavcodec/mpc7.c`
- **Type**: CWE-125 Out-of-bounds Read
- **Root cause**: `c->lastframelen` is stored without an upper-bound check against
  `MPC_FRAME_SIZE=1152`. Values up to 2047 (11-bit field) are accepted.

## Vulnerable Code Paths

### Step 1 — Unchecked extradata parse (`mpc7_decode_init`, line 111)

```c
skip_bits_long(&gb, 88);
c->gapless = get_bits1(&gb);
c->lastframelen = get_bits(&gb, 11);   // [0..2047], no upper-bound check
```

The AVFrame buffer is subsequently allocated for exactly `MPC_FRAME_SIZE=1152` samples:

```c
frame->nb_samples = MPC_FRAME_SIZE;
ff_get_buffer(avctx, frame, 0);
```

### Step 2 — nb_samples overwrite (`mpc7_decode_frame`, lines 280-281)

```c
ff_mpc_dequantize_and_synth(c, mb, (int16_t **)frame->extended_data, 2);
if(last_frame)
    frame->nb_samples = c->lastframelen;   // may be 2047 > 1152
```

Any downstream code (sample-format conversion, output muxer) that iterates over
`frame->nb_samples` samples from `frame->extended_data` will read up to
`(2047 - 1152) * 2 * 2 = 3580` bytes beyond the heap allocation.

## Extradata Bit Layout (After `bswap_buf`)

`mpc7_decode_init` byte-swaps the 16-byte extradata as four LE uint32 words, then
uses `init_get_bits` (MSB-first bit numbering):

| Bit range | Maps to            | Field         |
|-----------|--------------------|---------------|
| 0         | extradata[3] bit 7 | IS            |
| 1         | extradata[3] bit 6 | MSS           |
| 2-7       | extradata[3] bits 5:0 | maxbands   |
| 8-95      | (skipped 88 bits)  | —             |
| 96        | extradata[15] bit 7 | gapless      |
| 97-103    | extradata[15] bits 6:0 | lastframelen [10:4] |
| 104-107   | extradata[14] bits 7:4 | lastframelen [3:0]  |

**Formula**: `lastframelen = (extradata[15] & 0x7F) << 4 | (extradata[14] >> 4)`

To set `lastframelen = 2047 = 0x7FF`:
- `extradata[15] = 0x7F` (gapless=0, upper 7 bits = 0x7F)
- `extradata[14] = 0xF0` (lower 4 bits = 0xF)

The crafted file uses exactly these values.

## Why the Full OOB Cannot Be Triggered via the Stock MPC Demuxer

The `last_frame` flag that enables the nb_samples overwrite is set in
`libavformat/mpc.c:mpc_read_packet()`:

```c
pkt->data[1] = (c->curframe > c->fcount) && c->fcount;
```

For this to be 1, `c->curframe` must exceed `c->fcount` at that point. However,
the function begins with:

```c
if (c->curframe >= c->fcount && c->fcount)
    return AVERROR_EOF;
```

Because curframe is incremented inside the function AFTER this check, the post-
increment value can equal at most `c->fcount` (when the last valid frame is read:
old_curframe = fcount-1, new curframe = fcount). The condition `curframe > fcount`
(strict) is therefore never satisfied for any nonzero fcount.

When fcount=0 the EOF guard is disabled, but then `&& c->fcount` evaluates to 0,
so `pkt->data[1]` is still 0.

**Conclusion**: `pkt->data[1]` (the `last_frame` byte) is always 0 from the
standard MPC demuxer, making the nb_samples overwrite path dead code in practice
for this entry point.

## PoC File Structure

```
Offset  0   b'MP+'     -- MPC magic
Offset  3   0x07       -- SV7 version
Offset  4   0x01000000 -- fcount = 1 (LE uint32)
Offset  8   16 bytes   -- extradata (lastframelen=2047 encoded)
Offset 24   8 bytes    -- one minimal audio frame (size2=5, zero payload)
```

Total: 32 bytes.

## Runtime Result

The ASAN-instrumented build processes the file without any memory error:
- Demuxer parses correctly, codec initialises with `lastframelen=2047`
- Frame is decoded (1 frame of silence, `nb_samples` stays 1152 because last_frame=0)
- No heap-buffer-overflow is reported

## Status

`UNVERIFIED` — the extradata parsing bug (unchecked lastframelen) is confirmed
present in the source, but the trigger condition (last_frame=1) cannot be satisfied
through the standard MPC demuxer's packet construction logic.
