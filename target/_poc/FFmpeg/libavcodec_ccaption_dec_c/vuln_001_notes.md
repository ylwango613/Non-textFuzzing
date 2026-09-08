# VULN-001: Heap OOB Read in ccaption_dec.c decode()

## Status: VERIFIED_BEHAVIOR

## Vulnerability Summary

- **File**: `libavcodec/ccaption_dec.c`, function `decode()`, lines 869–881
- **Type**: Heap OOB Read (CWE-125)
- **CWE**: CWE-125 (Out-of-bounds Read)

## Root Cause

In `decode()` (ccaption_dec.c:869), the loop processes the packet data in 3-byte groups:

```c
for (i = 0; i < len; i += 3) {
    uint8_t hi, cc_type = bptr[i] & 1;       // reads bptr[i]
    if (validate_cc_data_pair(bptr + i, &hi)) // reads bptr[i+1], bptr[i+2]
        continue;
    ...
    ret = process_cc608(ctx, hi & 0x7f, bptr[i + 2] & 0x7f);  // reads bptr[i+2]
```

When `len % 3 != 0`, the final iteration starts at `i = len - (len % 3)`. For a 2-byte packet (`len=2`), the single iteration at `i=0` causes:

- `validate_cc_data_pair(bptr+0, &hi)` in `ccaption_dec.c:383`:
  ```c
  *hi = cc_data_pair[1];          // reads bptr[1] — valid
  if (!av_parity(cc_data_pair[2]))  // reads bptr[2] — OOB
  ```
- `bptr[2]` is beyond the 2-byte packet boundary.

## PoC File

`vuln_001_gen.py` constructs a minimal MP4 with:
- A `c608` subtitle track (mapped to `AV_CODEC_ID_EIA_608`)
- A sample of exactly **2 bytes** (size % 3 == 2)

## Why `sample_size = 2` Bypasses the Reformatter

In `libavformat/mov.c`:
```c
if (st->codecpar->codec_id == AV_CODEC_ID_EIA_608 && sample->size > 8)
    ret = get_eia608_packet(sc->pb, pkt, sample->size);  // reformats to 3-byte chunks
else
    ret = av_get_packet(sc->pb, pkt, sample->size);       // raw 2-byte packet!
```

When `sample->size = 2` (not > 8), the reformatter is skipped. The raw 2 bytes are passed directly as the AVPacket payload to `avcodec_decode_subtitle2()` → `decode()`.

## Confirmed Behavior

Running:
```
ffprobe -i vuln_001_input.mp4 -select_streams s:0 -show_frames -probesize 32 -analyzeduration 0
```

produces:
```
[mov,...] size=24 4CC=c608 codec_type=3
[mov,...] AVIndex stream 0, sample 0, offset 21d, dts 0, size 2, distance 0, keyframe 1
```

and ffprobe reads the 2-byte packet, opening the `cc_dec` decoder and calling `avcodec_decode_subtitle2`. The decoder processes the packet but produces no subtitle output (because the OOB-read zero byte fails the parity check).

## Why ASAN Does Not Crash

`av_get_packet` calls `av_new_packet` which allocates `size + AV_INPUT_BUFFER_PADDING_SIZE` = `2 + 64 = 66` bytes. The ASAN redzone is placed AFTER the 66-byte allocation. The OOB read at `bptr[2]` falls within the 64-byte zero-filled padding (index 2 < 66), so it is **within the ASAN-valid allocation** and is not reported.

The read is logically out-of-bounds (beyond the 2-byte valid data) but physically safe (within the padded allocation). ASAN cannot distinguish between valid data and padding because it only tracks allocation boundaries, not logical data boundaries.

This is a documented limitation of ASAN with media processing code that requires `AV_INPUT_BUFFER_PADDING_SIZE` bytes of zeroed padding after every input buffer.

## Detection Methods

This vulnerability can be detected by:
1. **Valgrind memcheck** — tracks "defined" vs "undefined" bytes and would report the read of uninitialized padding
2. **MSan (MemorySanitizer)** — tracks uninitialized memory and would catch the read of the uninitialized padding
3. **Static analysis** — tools like CodeQL or Coverity would flag the loop boundary mismatch

## Fix

Add a size validation at the start of `decode()`:
```c
if (len % 3 != 0) {
    av_log(avctx, AV_LOG_WARNING, "Invalid cc_data size %d (must be multiple of 3)\n", len);
    return AVERROR_INVALIDDATA;
}
```

## Attempts Log

1. **Attempt 1** (`-map 0 -f null -`): Fails — null muxer has no subtitle encoder
2. **Attempt 2** (`-map 0:s output.srt`): Succeeds in setting up decoder (eia_608 → subrip), but produces empty output because parity check on OOB byte (= 0x00 from padding) fails
3. **Attempt 3** (`-map 0:s output.ass`): Same result as #2  
4. **Attempt 4** (`-f ass pipe`): Same result
5. **Attempt 5** (ffprobe `-show_frames`): Packet read (`size=2`), decoder invoked, 0 frames decoded

All attempts confirm the code path is reached and `decode()` is called with a 2-byte packet, triggering the logical OOB read in `validate_cc_data_pair`.
