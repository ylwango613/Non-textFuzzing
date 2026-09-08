# VULN-001 Notes: OOB Heap Read in ff_combine_frame via dnxuc_parse

## Vulnerability Summary

- **File**: `libavcodec/dnxuc_parser.c`, lines 59–72
- **CWE**: CWE-125 Out-of-bounds Read
- **Path**: `dnxuc_parse()` → `ff_combine_frame()` → `memcpy()` reads 57 bytes from a 1-byte source

When the 8-byte 'pack' marker (`[SIZE_BE 4 bytes][p][a][c][k]`) straddles two consecutive
`av_parser_parse2` calls such that the first 7 bytes (`[SIZE][p][a][c]`) were accumulated into
`pc->state64` in prior calls and only `k` arrives in the current `buf[]`:

```c
// dnxuc_parser.c ~line 62
if (ipc->pc.index + i >= 7 && (uint32_t)state == MKBETAG('p','a','c','k')) {
    next = i - 7;   // i=0 => next = -7
    ...
}
// parser.c ~line 272
if (next > -AV_INPUT_BUFFER_PADDING_SIZE)   // -7 > -64: TRUE
    memcpy(&pc->buffer[pc->index], *buf,
           next + AV_INPUT_BUFFER_PADDING_SIZE);  // copies 57 bytes from 1-byte source
```

## PoC Approach

**Format chosen**: MXF (Material eXchange Format) — the only demuxer in this FFmpeg build
that supports AV_CODEC_ID_DNXUC via `mxf_picture_essence_container_uls` / `ff_mxf_codec_uls`.

**Wrapping trigger**: The DNXUC essence container UL used in tag `0x3004` is NOT listed in
`mxf_picture_essence_container_uls` (mxfdec.c ~line 1630), so the demuxer sets
`wrapping = UnknownWrapped`. This causes `mxf_parse_structural_metadata` (mxfdec.c ~line 3141)
to set `need_parsing = AVSTREAM_PARSE_TIMESTAMPS`, which makes `parse_packet()` invoke
`av_parser_parse2()` → `dnxuc_parse()` for every AVPacket.

**Split payload**:
```
Essence KLV 1 (7 bytes data): 00 00 00 08  70 61 63   → size=8, "pac"
Essence KLV 2 (1 byte data):  6B                      → "k"
```

After KLV 1: `pc->index = 7`, `pc->state64 = 0x0000_0008_7061_6300` (not yet 'pack')
After KLV 2 byte 0: `state = (state64 << 8) | 0x6B = 0x_0000_0008_7061_636B`
  - `(uint32_t)state = 0x7061_636B = MKBETAG('p','a','c','k')` → MATCH at `i=0`
  - `next = 0 - 7 = -7` → OOB memcpy triggered

**Single-stream bypass**: `mxf_get_stream_index` (mxfdec.c ~line 521) falls back to returning
stream 0 when `nb_streams == 1`, so the essence track_number need not match exactly.

## Run Results

```
Stream #0:0: Video: dnxuc, none(progressive), 1920x1080, 25 tbr
[in#0] wrapping of stream 0 is unknown
frame=1 fps=0.0, EXIT=0
```

The MXF file is successfully parsed; the DNXUC stream is identified with UnknownWrapped,
confirming the parser IS invoked. No ASAN crash was generated.

## Why ASAN Does Not Fire

`mxf_read_packet` calls `av_get_packet(s->pb, pkt, size)`, which internally calls
`av_new_packet()`. This allocates `size + AV_INPUT_BUFFER_PADDING_SIZE = 1 + 64 = 65` bytes
for the 1-byte KLV 2 payload. The `memcpy` in `ff_combine_frame` reads
`57 = -7 + 64` bytes starting at `*buf[0]`, accessing indices 0..56. All 57 indices fall
within the 65-byte allocation, so ASAN sees no out-of-bounds access.

The vulnerability is theoretically reachable: if a future code path delivers the 1-byte
chunk without the `AV_INPUT_BUFFER_PADDING_SIZE` padding (e.g., via a custom decoder that
calls `av_parser_parse2` directly with a stack/heap buffer of exactly 1 byte), the 56-byte
OOB read would trigger. Via the `ffmpeg` CLI + MXF + `av_get_packet`, the padding absorbs
the overread.

## Status Rationale

Status: **UNVERIFIED** — The correct code path is reached (parser invoked, correct split
boundary), but ASAN does not detect the OOB read because `av_get_packet` padding makes the
57-byte memcpy land within the allocation.
