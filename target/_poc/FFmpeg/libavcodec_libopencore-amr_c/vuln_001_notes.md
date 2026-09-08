# VULN 001 – AMR-NB Decoder buf[0] OOB Read Before Size Check

## Vulnerability Location

**File**: `libavcodec/libopencore-amr.c`
**Function**: `amr_nb_decode_frame()`
**Lines**: 103–125

## Root Cause

```c
// line 118 – buf[0] read BEFORE size check
dec_mode    = (buf[0] >> 3) & 0x000F;
packet_size = block_size[dec_mode] + 1;

// line 121 – size guard arrives too late
if (packet_size > buf_size) { … return AVERROR_INVALIDDATA; }
```

`buf` is set from `avpkt->data`. If `avpkt->size == 0` and `avpkt->data == NULL`
(the standard representation of a zero-byte packet in FFmpeg), dereferencing
`buf[0]` is a **NULL pointer dereference (CWE-476)**.

If `avpkt->data` points to a valid allocation but `avpkt->size == 0`, reading
`buf[0]` is a **one-byte heap out-of-bounds read (CWE-125)**.

## Attack Vector

A crafted AMR-NB file → ffmpeg `-i crafted.amr` → amr/amrnb demuxer →
`avcodec_send_packet()` → `amr_nb_decode_frame()` → `buf[0]` OOB at line 118.

## AMR-NB File Format

```
#!AMR\n  (6-byte magic)
[mode_byte][payload bytes …]  (repeated frames)
```

Mode byte bits: `[P(1)][FT(4)][Q(1)][P(2)]`
FT (bits 6–3) determines payload length:

| FT | amrnb_packed_size (demuxer) | block_size (decoder) |
|----|-----------------------------|----------------------|
|  0 | 13                          | 12                   |
|  8 | 6                           |  5  (SID)            |
|9–15| 1                           |  0                   |

## Crafted Inputs

| File                        | Content                        | Expected effect |
|-----------------------------|--------------------------------|-----------------|
| `vuln_001_input.amr`        | magic + FT=9 mode byte ×500    | Passes size guard; Decoder_Interface_Decode called with 1 byte; opencore-amr OOB |
| `vuln_001_input_trunc.amr`  | magic + 1 FT=0 mode byte       | At EOF: 1-byte packet flushed; decoder reads buf[0] then detects short frame |
| `vuln_001_input_ft15.amr`   | magic + FT=15 mode byte ×500   | Same as FT=9 path |
| `vuln_001_input_mixed.amr`  | magic + FT=9 ×10 + FT=0 trunc  | Mixed path |
| `vuln_001_input_empty.amr`  | magic only (0 frame bytes)      | Tests flush/drain path |

## Fix Recommendation

Add a size guard **before** reading `buf[0]`:

```c
if (buf_size < 1) {
    av_log(avctx, AV_LOG_ERROR, "AMR-NB packet too short\n");
    return AVERROR_INVALIDDATA;
}
dec_mode    = (buf[0] >> 3) & 0x000F;
```

## References

- CWE-125: Out-of-bounds Read
- CWE-476: NULL Pointer Dereference
