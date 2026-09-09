# VULN 001 — Heap OOB Read in `parse_speex_extradata`

## Vulnerability Location

`libavcodec/speexdec.c`, function `parse_speex_extradata`, lines 1401–1441.

## Root Cause

`parse_speex_extradata` accepts an `extradata` buffer and its size.
It locates the Speex magic string with:

```c
const uint8_t *buf = av_strnstr(extradata, "Speex   ", extradata_size);
```

The only size guard is that `extradata_size >= 80` (checked in
`speex_decode_init`).  After finding the magic at offset P the function advances
the pointer by 28 (`buf += 28`) and performs:

- nine `bytestream_get_le32(&buf)` calls (each advances buf by 4)
- one `buf += 4` skip
- one final `bytestream_get_le32(&buf)` call

consuming **44 bytes** in total: bytes `[P+28 .. P+71]` inclusive.

When P > 0 the read window exceeds an exactly-80-byte buffer.  For P = 9:

```
reads: extradata[37 .. 80]   (last byte: index 80, one past the 80-byte buffer)
```

The last read (`s->extra_headers = bytestream_get_le32(&buf)`) accesses bytes
[77, 78, 79, **80**] — a one-byte heap out-of-bounds read.

## Why ASAN May Not Fire

`ff_alloc_extradata` always allocates `size + AV_INPUT_BUFFER_PADDING_SIZE`
bytes (size + 64) via `av_mallocz`.  ASAN places its red zone after the full
144-byte allocation, not after byte 79.  Reading byte[80] therefore lands in
the zeroed padding region and is invisible to ASAN's shadow memory in this
FFmpeg build.

The logic defect is real and would be exploitable in any context where extradata
is allocated without the extra padding (e.g., a direct `av_malloc(80)` call by
an integrator).

## Trigger Path

```
ffmpeg -i crafted.mkv -f null -
  → avformat_open_input()
  → matroska_read_header()        A_MS/ACM codec type → ff_get_wav_header()
                                  maps wFormatTag=0xA109 → AV_CODEC_ID_SPEEX
                                  extradata = codec_priv[18..97] (80 bytes)
  → avcodec_open2()
  → speex_decode_init()           extradata_size == 80 >= 80 → calls parse_speex_extradata
  → parse_speex_extradata()       finds "Speex   " at P=9 → OOB read at byte[80]
```

## PoC Strategy

`vuln_001_gen.py` builds a minimal Matroska (.mkv) file in pure Python with no
FFmpeg API calls.  The container uses CodecID `A_MS/ACM` (Microsoft Audio Codec
Manager) so that the matroska demuxer processes the `CodecPrivate` field through
`ff_get_wav_header`.

**CodecPrivate layout (98 bytes):**

```
 0-17 : WAVEFORMATEX (18 bytes)
        wFormatTag     = 0xA109  (Speex RIFF tag, maps to AV_CODEC_ID_SPEEX)
        nChannels      = 1
        nSamplesPerSec = 16000
        cbSize         = 0        ← prevents ff_get_wav_header from
                                    consuming extradata internally

18-97 : crafted 80-byte Speex extradata
        offset  0– 8 : 0x00 × 9          (pre-magic padding)
        offset  9–16 : b'Speex   '        (magic at P = 9)
        offset 17–44 : 0x00 × 28         (skip zone / version_id area)
        offset 45–48 : LE32(16000)        (rate > 0 check ✓)
        offset 49–52 : LE32(0)            (mode = 0, NB, valid 0-2 ✓)
        offset 53–56 : LE32(4)            (bitstream_version == 4 ✓)
        offset 57–60 : LE32(1)            (nb_channels = 1, valid 1-2 ✓)
        offset 61–64 : LE32(0)            (bitrate, no check)
        offset 65–68 : LE32(160)          (frame_size >= NB_FRAME_SIZE=160 ✓)
        offset 69–72 : LE32(0)            (vbr, no check)
        offset 73–76 : LE32(1)            (frames_per_packet = 1, valid 1-64 ✓)
        offset 77–79 : 0x00 × 3           (extra_headers bytes 0-2, in-bounds)
        offset 80    : ← OOB READ (4th byte of extra_headers LE32)
```

With `cbSize = 0`, `ff_get_wav_header` does not allocate extradata.  The matroska
demuxer then copies `codec_priv[18..97]` (80 bytes) as the stream's extradata.
`speex_decode_init` sees `extradata_size == 80 >= 80` and calls
`parse_speex_extradata`, which passes all validation checks before executing the
out-of-bounds read.

## How to Run

```bash
bash vuln_001_run.sh
```

Output is collected in `vuln_001_result.txt`; ASAN logs (if any) are appended
from `asan.log.*`.  The expected result is **UNVERIFIED** (code path exercised,
no ASAN crash due to 64-byte padding).
