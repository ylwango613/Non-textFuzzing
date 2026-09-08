# VULN 001 – Integer Overflow in g723_1 Parser (CWE-190 → CWE-125)

## Vulnerability

File: `libavcodec/g723_1_parser.c`, line 41  
Function: `g723_1_parse()`

```c
next = frame_size[buf[0] & 3] * FFMAX(1, avctx->ch_layout.nb_channels);
```

`frame_size[]` values are `uint8_t` (24, 20, 4, 1).  
`nb_channels` is `int`.  
No overflow check before the multiplication.

With `nb_channels = 178956971 (0x0AAAAAAB)`:
- Type-0 frame: `24 * 178956971 = 4294967304` → wraps to `8` (int32 signed overflow, UB)
- Type-1 frame: `20 * 178956971 = 3579139420` → wraps to `-715827876` (negative → OOB read via ff_combine_frame)

## Input File

**Container:** Matroska (MKV), 167 bytes  
**Generator:** `vuln_001_gen.py` (Python, no compilation)

### Key construction details

1. **Codec track**: `A_MS/ACM` with a 14-byte WAVEFORMATEX codec private:
   - `wFormatTag = 0x0042` (G.723.1) — causes `par->codec_id = AV_CODEC_ID_G723_1`
   - `nChannels = 0` — key trick: makes `av_channel_layout_check()` return 0 (invalid),
     so `mka_parse_audio()` falls through to line 2886 and sets
     `par->ch_layout.nb_channels = track->audio.channels`

2. **EBML Channels element** (`0x9F`): set to `178956971`
   - This 64-bit EBML UINT is unrestricted; `track->audio.channels` becomes 178956971
   - MKV demuxer sets `need_parsing = AVSTREAM_PARSE_HEADERS` for non-AAC audio (line 2895 matroskadec.c)

3. **Audio payload**: 24-byte G.723.1 type-0 frame (first byte `0x00`, low 2 bits = 0)
   - Delivered as a MKV SimpleBlock

## Trigger Path

```
ffmpeg -codec_whitelist 'none' -i vuln_001_input.mkv -f null -
```

Detailed call chain in `avformat_find_stream_info()`:

1. `av_parser_init(AV_CODEC_ID_G723_1)` → g723_1 parser created  
2. `avcodec_parameters_to_context(sti->avctx, par)` → `avctx->ch_layout.nb_channels = 178956971`  
3. `avcodec_open2(avctx, g723_1_decoder, ...)`:
   - Whitelist check (`-codec_whitelist 'none'`) fails at avcodec.c line 189–191
   - This is **before** `avctx->internal` is allocated (line 201)
   - `return AVERROR(EINVAL)` — no `ff_codec_close()`, no `av_opt_free()`
   - `avctx->ch_layout.nb_channels` is **NOT reset** (stays at 178956971)
4. Packet read loop: `read_frame_internal()` → `parse_packet()` → `av_parser_parse2()`
5. `g723_1_parse()`:
   ```c
   next = frame_size[0] * FFMAX(1, 178956971);
        = 24 * 178956971 = 4294967304  // SIGNED INT OVERFLOW
   ```
6. UBSAN reports: `runtime error: signed integer overflow: 24 * 178956971 cannot be represented in type 'int'`

## Why `-codec_whitelist 'none'` is Needed

Without this option, `avcodec_open2` fails at the `FF_SANE_NB_CHANNELS = 512` check
(avcodec.c line 287–290). At that point `avctx->internal` is already allocated (line 201),
so `ff_codec_close()` → `av_opt_free(avctx)` is called, which uninits `avctx->ch_layout`
(resetting `nb_channels` to 0). The parser then sees `nb_channels = 0` and uses
`FFMAX(1, 0) = 1`, producing no overflow.

With `-codec_whitelist 'none'`, the failure occurs at line 189–191 (before line 201),
so `avctx->ch_layout` is never reset.

## Observed Output (ASAN+UBSAN Build)

```
[g723_1 @ ...] Codec (g723_1) not on whitelist 'none'
[in#0/matroska,webm @ ...] Failed to open codec in avformat_find_stream_info
src/libavcodec/g723_1_parser.c:41:14: runtime error: signed integer overflow: 24 * 178956971 cannot be represented in type 'int'
Stream #0:0(eng): Audio: g723_1, 8000 Hz, 178956971 channels
```

## Impact in Release Build

Without sanitizers, the signed multiplication wraps (implementation-defined on most
platforms). For type-1 frames the result is `-715827876`, which is passed to
`ff_combine_frame()`. That function uses `next` as a target buffer size, so a negative
value leads to an **out-of-bounds read** on the `ParseContext.buffer` heap allocation.
This is a potential information-disclosure or crash (CWE-125).

## Files

| File | Description |
|------|-------------|
| `vuln_001_gen.py` | Python generator for the crafted MKV file |
| `vuln_001_run.sh` | Shell runner (`ffmpeg -codec_whitelist 'none' ...`) |
| `vuln_001_input.mkv` | Generated malformed input (167 bytes) |
| `vuln_001_status.txt` | Status: VERIFIED_BEHAVIOR |
| `vuln_001_result.txt` | Raw ffmpeg output with UBSAN error |
