# SBC Parser Heap OOB Read - PoC Notes

## Vulnerability

**File**: `libavcodec/sbc_parser.c`  
**Lines**: 89–94  
**CWE**: CWE-125 (Out-of-bounds Read)

### Vulnerable Code

```c
if (pc->header_size) {
    memcpy(pc->header + pc->header_size, buf,
           sizeof(pc->header) - pc->header_size);   // <-- no buf_size check
    next = sbc_parse_header(s, avctx, pc->header, sizeof(pc->header))
         - pc->buffered_size;
    pc->header_size = 0;
}
```

`pc->header[3]` is a 3-byte temporary buffer. When `header_size = 1`, the memcpy
copies `sizeof(pc->header) - 1 = 2` bytes from `buf` without verifying that
`buf_size >= 2`. If `buf_size = 1`, byte `buf[1]` is read beyond the declared
buffer boundary.

## Trigger Mechanism

The `raw_packet_size` option of the SBC raw demuxer (`libavformat/sbcdec.c`) maps
directly to `FFRawDemuxerContext.raw_packet_size` via the `ff_raw_demuxer_class`
AVOptions. Setting `-raw_packet_size 1` causes `ff_raw_read_partial_packet` to read
exactly 1 byte per `read_packet` call, so `av_parser_parse2` / `sbc_parse` receives
exactly 1 byte per invocation.

**Two-call trigger sequence**:

1. **Call 1** – buf = `[0x9C]`, buf_size = 1  
   - `pc->header_size = 0` → takes the `else` branch  
   - `sbc_parse_header` returns -1 (len < 3)  
   - `pc->header_size = FFMIN(3, 1) = 1`; `pc->header[0] = 0x9C`  
   - `pc->buffered_size = 1`; next = END_NOT_FOUND  

2. **Call 2** – buf = `[0x00]`, buf_size = 1  
   - `pc->header_size = 1` → takes the `if` branch  
   - `memcpy(pc->header + 1, buf, 2)` — copies 2 bytes from a 1-byte `buf`  
   - **OOB read**: `buf[1]` is beyond `buf_size`  

## Why ASAN Does NOT Detect It

`av_new_packet(pkt, 1)` allocates `1 + AV_INPUT_BUFFER_PADDING_SIZE` = `1 + 64 = 65`
bytes (see `libavcodec/defs.h`, line 40). The ASAN red-zone begins only after the 65th
byte. The OOB memcpy reads `buf[1]`, which is the first byte of the padding region —
byte index 1 of a 65-byte allocation — so ASAN does not flag it.

The `av_parser_parse2` API contract (avcodec.h line 2812–2813) explicitly states:
> "buf_size … without the padding. The full buffer size is assumed to be
> buf_size + AV_INPUT_BUFFER_PADDING_SIZE."

So the parser contract allows reads up to `buf_size + 64` bytes. The bug reads only
`buf_size + 1` bytes, which is within the contract-guaranteed padding, preventing
ASAN detection in the standard pipeline.

A potential secondary OOB in `ff_combine_frame` (line 273–274: `memcpy` of
`next + AV_INPUT_BUFFER_PADDING_SIZE` bytes from `*buf`) is blocked by the early
`if (next > *buf_size) return AVERROR(EINVAL)` guard (line 227) because
`next` (= frame_length − buffered_size = 5) > `buf_size` (= 1).

## Approaches Tried

| # | Input | ffmpeg options | Result |
|---|-------|----------------|--------|
| 1 | 8-byte SBC (0x9C × 1 + 0x00 × 7) | `-f sbc -raw_packet_size 1` | OOB read into padding; decoder error, no ASAN |
| 2 | 2-byte SBC (0x9C 0x00) | `-f sbc -raw_packet_size 1` | Same; 1 packet(1 byte) reported |
| 3 | 4-byte MSBC (0xAD 0x00 × 3) | `-f sbc -raw_packet_size 1` | Same behavior |
| 4 | Named pipe: `printf '\x9c'; sleep 2; printf '\x00'` | `-f sbc -raw_packet_size 1` | Same; timing doesn't change allocation |
| 5 | 5-byte SBC | `-f sbc -raw_packet_size 1` | Same |
| 6 | 8-byte file via `dd bs=1` pipe | `-f sbc -raw_packet_size 1` | Same |

All approaches successfully exercised the vulnerable code path:

- The decode error "error rate 1 exceeds maximum 0.666667" is a direct consequence
  of the OOB read returning padding zero bytes (bitpool=0), causing the parser to
  compute a frame length (6 bytes) that exceeds the available data (1 byte), leading
  to AVERROR(EINVAL) and packet discard.

- `probesize` minimum is 32 bytes; `-probesize 1` is rejected by ffmpeg with
  "out of range". The option was removed from subsequent runs.

## Conclusion

The vulnerable `memcpy` at sbc_parser.c:90–91 is executed on the second 1-byte
parser call. It reads 1 byte past `buf_size` into the AV_INPUT_BUFFER_PADDING_SIZE
region. This constitutes a **specification-level OOB read** that is undetectable with
ASAN in the standard ffmpeg pipeline due to guaranteed padding, but IS detectable as
abnormal behavior (spurious decode errors, incorrect frame-size computation from
unintended data).

In a non-standard environment (no padding, or stack-allocated buf), this would be a
genuine exploitable read. The code fix is to add the check:
```c
if (buf_size < (int)(sizeof(pc->header) - pc->header_size)) {
    /* handle short buffer: treat as new header-size situation */
    ...
}
```
