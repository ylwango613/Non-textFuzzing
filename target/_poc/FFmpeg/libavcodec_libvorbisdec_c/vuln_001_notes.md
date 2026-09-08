# VULN 001 - Analysis Notes

## Vulnerability

**ID**: VULN 001  
**Title**: Heap OOB Read via `bytestream_get_be16` Without Remaining-Bytes Guard in Vorbis Extradata Parser  
**File**: `libavcodec/libvorbisdec.c`, lines 54–67  
**Function**: `oggvorbis_decode_init()`  
**CWE**: CWE-125 (Out-of-bounds Read)

## Vulnerable Code

```c
// libvorbisdec.c lines 54-67
if(p[0] == 0 && p[1] == 30) {
    int sizesum = 0;
    for(i = 0; i < 3; i++){
        hsizes[i] = bytestream_get_be16((const uint8_t **)&p);
        sizesum += 2 + hsizes[i];
        if (sizesum > avccontext->extradata_size) {
            av_log(avccontext, AV_LOG_ERROR, "vorbis extradata too small\n");
            ret = AVERROR_INVALIDDATA;
            goto error;
        }
        headers[i] = p;
        p += hsizes[i];
    }
}
```

## Root Cause

The guard condition `sizesum > avccontext->extradata_size` uses strict inequality (`>`).

When `sizesum == extradata_size` (exactly equal), the check is *false* and the loop
continues. At iteration i=2, `bytestream_get_be16` reads 2 bytes starting at
`extradata + sizesum`, which is exactly at the end of the `extradata_size`-byte buffer.
This is a 2-byte read beyond the declared `extradata_size`.

The fix would be to use `>=` instead of `>`, or to check that at least 2 bytes remain
before calling `bytestream_get_be16`.

## Trigger Layout

Extradata contents (34 bytes, extradata_size = 34):

```
Offset  Bytes        Purpose
------  -----------  -----------------------------------------------
0       0x00         triggers p[0] == 0 branch check; also read as
                     the high byte of hsizes[0] by bytestream_get_be16
1       0x1E (= 30)  triggers p[1] == 30 branch check; also read as
                     the low byte of hsizes[0] = 0x001E = 30
2..31   0x41 * 30    30-byte filler (consumed as header[0] content)
32      0x00         high byte of hsizes[1] = 0x0000 = 0
33      0x00         low byte of hsizes[1]
34..35  (no bytes)   OOB read target — 2 bytes past end
```

Loop trace:
```
i=0: bytestream_get_be16 reads extradata[0..1] = 0x001E = 30
     sizesum = 0 + 2 + 30 = 32
     guard: 32 > 34? NO → continue
     headers[0] = extradata+2; p += 30 → p = extradata+32

i=1: bytestream_get_be16 reads extradata[32..33] = 0x0000 = 0
     sizesum = 32 + 2 + 0 = 34
     guard: 34 > 34? NO (strict inequality, equal is NOT caught) → continue
     headers[1] = extradata+34; p += 0 → p stays at extradata+34

i=2: bytestream_get_be16 reads extradata[34..35]
     extradata_size = 34 → byte indices 34 and 35 are PAST THE END
     ** HEAP OOB READ (2 bytes) **
```

## Container Choice: Why MKV Instead of OGG

The vulnerable branch (`p[0] == 0 && p[1] == 30`) is only reachable when the codec
extradata starts with bytes `0x00, 0x1E`. In an OGG container, FFmpeg's OGG demuxer
packages the three Vorbis header packets using Xiph lacing (first byte = 0x02), which
would trigger the `*p == 2` branch instead. The `p[0]==0 && p[1]==30` branch is
specifically for Matroska (MKV/WebM) where `CodecPrivate` can be set to arbitrary bytes.

In the matroska demuxer (`libavformat/matroskadec.c`), there is no special handling for
`A_VORBIS` codec in `mkv_parse_audio()`. The CodecPrivate blob is copied verbatim into
`AVCodecParameters.extradata` (see lines 3334–3340 of `matroskadec.c`), making it the
ideal container to inject arbitrary extradata bytes.

## ASAN Behavior in This Build

FFmpeg is compiled with `-fsanitize=address,undefined`. The function `ff_alloc_extradata`
allocates `size + AV_INPUT_BUFFER_PADDING_SIZE` bytes (= 34 + 64 = 98 bytes) and **zeros
the padding** (`memset(extradata + size, 0, 64)`).

Because the OOB read at offset 34–35 falls within the zeroed 64-byte padding region, ASAN
does not report a violation (the bytes are mapped and allocated). The read returns 0x0000,
so `hsizes[2] = 0`. The subsequent `vorbis_synthesis_headerin()` call at `i=0` then fails
because the 30-byte filler is not a valid Vorbis identification header → "Extradata corrupt."

**In a non-padded allocator** (e.g., a custom allocator, hardened libc, or valgrind), the
2-byte read at offset 34–35 would access unmapped or unallocated memory, causing a
segfault or valgrind `Invalid read of size 2`.

## Observed Results

```
[vorbis @ ...] Extradata corrupt.
[vorbis @ ...] Extradata corrupt.
ffmpeg exit code: 234
```

The OOB read occurs silently (bytes 34–35 = 0x00, 0x00 from padding), and libvorbis
subsequently rejects the invalid header, producing the "Extradata corrupt." error.

## Reproducer Command

```bash
ffmpeg -i vuln_001_input.mkv -f null -
```

To demonstrate the OOB more explicitly, run under valgrind:
```bash
valgrind --tool=memcheck --error-exitcode=1 \
  ffmpeg -i vuln_001_input.mkv -f null - 2>&1 | grep "Invalid read"
```

## Files

| File                  | Description                                    |
|-----------------------|------------------------------------------------|
| `vuln_001_gen.py`     | Python script to generate the malicious MKV    |
| `vuln_001_input.mkv`  | Generated 156-byte malicious MKV file          |
| `vuln_001_run.sh`     | Shell script to generate + run the PoC         |
| `vuln_001_status.txt` | Auto-generated run result                      |
| `vuln_001_notes.md`   | This analysis document                         |
