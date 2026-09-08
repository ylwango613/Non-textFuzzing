# VULN 001: avpriv_adts_header_parse OOB Read — PoC Notes

## Summary

The vulnerability is in `libavcodec/adts_parser.c:66`:

```c
int avpriv_adts_header_parse(AACADTSHeaderInfo **phdr, const uint8_t *buf, size_t size) {
    if (!phdr || !buf || size < AV_AAC_ADTS_HEADER_SIZE)  // only checks size >= 7
        return AVERROR_INVALIDDATA;
    ...
    ret = ff_adts_header_parse_buf(buf, *phdr);  // BUG: buf not padded
}
```

`ff_adts_header_parse_buf` requires its buffer to be
`AV_AAC_ADTS_HEADER_SIZE + AV_INPUT_BUFFER_PADDING_SIZE` = 7 + 64 = **71 bytes**,
because the optimized bit reader (`UPDATE_CACHE_BE_32`) calls `AV_RB64(buf)` which
reads 8 bytes atomically. Passing only a 7-byte buffer reads 1 byte past the
declared end.

Compare with `av_adts_header_parse` (the public API, same file) which correctly
copies to a local `tmpbuf[71]` padded buffer first.

## Trigger Path

```
ffmpeg -allowed_extensions ALL -i vuln_001_input.m3u8 -f null -
  → hls.c: reads M3U8 with EXT-X-KEY METHOD=SAMPLE-AES
  → hls.c:2807: key_type == KEY_SAMPLE_AES → ff_hls_senc_decrypt_frame(AV_CODEC_ID_AAC, ...)
  → hls_sample_encryption.c:decrypt_audio_frame()
  → hls_sample_encryption.c:get_next_adts_frame()
  → hls_sample_encryption.c:289: avpriv_adts_header_parse(&adts_hdr, frame->data, 7)
  → adts_parser.c:66: ff_adts_header_parse_buf(buf, *phdr)
  → adts_header.c:80: init_get_bits8(&gb, buf, 7)
  → adts_header.c: ff_adts_header_parse(&gb, hdr)
  → get_bits.h: UPDATE_CACHE_BE_32 → AV_RB64(buf)  [reads 8 bytes from 7-byte buffer]
```

## PoC Files

- `vuln_001_gen.py`: Generates `segment.ts`, `poc_key.bin`, `vuln_001_input.m3u8`
- `segment.ts`: Minimal 3-packet MPEG-TS (PAT + PMT + PES with 7-byte ADTS frame)
- `poc_key.bin`: 16-byte all-zero AES key (decryption doesn't execute since frame data = header only)
- `vuln_001_input.m3u8`: HLS playlist with `METHOD=SAMPLE-AES` triggering the vulnerable path

## Crafted ADTS Header

The 7-byte ADTS header in the PES payload: `FF F1 4C 40 00 FF FC`

| Field               | Value  | Notes                                     |
|---------------------|--------|-------------------------------------------|
| sync word           | 0xFFF  | triggers ADTS detection                   |
| ID                  | 0      | MPEG-4                                    |
| protection_absent   | 1      | no CRC, header_length = 7                 |
| profile             | 01     | AAC-LC (object_type = 2)                  |
| sampling_index      | 3      | 48000 Hz (passes sample rate check)       |
| channel_config      | 1      | mono                                      |
| frame_length        | 7      | equals AV_AAC_ADTS_HEADER_SIZE (min valid)|
| buffer_fullness     | 0x7FF  | VBR                                       |
| num_raw_blocks      | 0      | 1 AAC block                               |

With `frame_length = 7` and `header_length = 7`, the subsequent checks in
`decrypt_audio_frame` pass cleanly:
- `frame.length < frame.header_length` → `7 < 7` → false (OK)
- `frame.length > ctx.buf_end - frame.data` → `7 > 7` → false (OK)
- `frame.length - frame.header_length > 31` → `0 > 31` → false (no AES decrypt invoked)

## Observed Behavior

The full trigger path **IS** executed:
- Key file is read
- AAC stream is detected (`aac (LC), mono`)
- One 7-byte packet is processed
- Decoder encounters the truncated frame and reports "Input buffer exhausted"

However, ASAN does **NOT** report a crash.

## Why ASAN Does Not Trigger

The OOB read (1 byte past the 7-byte buffer) falls within FFmpeg's standard
`AV_INPUT_BUFFER_PADDING_SIZE = 64` bytes of zero-padding that `av_new_packet(pkt, 7)`
appends to every packet allocation. The actual heap allocation is 71 bytes
(7 data + 64 padding), and `AV_RB64(buf)` reads bytes 0–7, where byte 7 is the
first padding byte — still within the allocation bounds known to ASAN.

ASAN would only fire if:
1. An external caller passes a stack/heap buffer of exactly 7 bytes to
   `avpriv_adts_header_parse` without additional padding, **or**
2. The packet buffer is created via `av_packet_from_data()` wrapping an
   externally-allocated buffer of exactly 7 bytes (no ASAN-accessible tail bytes)

## Root Cause vs. Public API

The public API `av_adts_header_parse()` in the same file does this correctly:

```c
uint8_t tmpbuf[AV_AAC_ADTS_HEADER_SIZE + AV_INPUT_BUFFER_PADDING_SIZE];  // 71 bytes
memcpy(tmpbuf, buf, AV_AAC_ADTS_HEADER_SIZE);
err = ff_adts_header_parse_buf(tmpbuf, &hdr);   // safe: 71-byte stack buffer
```

The fix for `avpriv_adts_header_parse` is the same: copy to a padded local buffer
before calling `ff_adts_header_parse_buf`.
