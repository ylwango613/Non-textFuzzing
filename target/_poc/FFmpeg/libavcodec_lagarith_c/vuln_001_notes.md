# VULN 001 – Out-of-Bounds Read in lag_decode_frame()

## Vulnerability

- **File**: `libavcodec/lagarith.c`
- **Function**: `lag_decode_frame()`
- **Lines**: 574-577, 631
- **CWE**: CWE-125 (Out-of-bounds Read)

## Root Cause

`lag_decode_frame()` reads from the packet buffer (`buf`) at offsets 0, 1, and 5 (and potentially further) without first verifying that `buf_size` is large enough to contain those bytes. If `buf_size < 9`, the reads at `buf[0]`, `*(buf+1)`, and `*(buf+5)` access memory beyond the allocated packet buffer.

## PoC Approach

`vuln_001_gen.py` constructs a minimal but structurally valid AVI file containing:
- A proper RIFF/AVI header with `avih`, `strl`/`strh`/`strf` chunks declaring a Lagarith (`LAGS`) video stream.
- A `movi` LIST containing one `00dc` video frame chunk whose payload is only **4 bytes** (`\x00\x00\x00\x00`), far below the 9-byte minimum `lag_decode_frame()` implicitly requires.
- A corresponding `idx1` index entry so the AVI demuxer correctly identifies and dispatches the packet to the decoder.

## Trigger Path

```
ffmpeg -i vuln_001_input.avi -f null -
  -> avformat_open_input()
  -> av_read_frame()          (AVI demuxer sends 4-byte packet)
  -> avcodec_send_packet()
  -> lag_decode_frame()
  -> reads buf[0], buf+1, buf+5 without bounds check  <-- OOB read
```

## Expected ASAN Output

With an ASAN-instrumented build, the run should produce a report along the lines of:

```
==<pid>==ERROR: AddressSanitizer: heap-buffer-overflow on address ...
READ of size 1 at 0x... thread T0
    #0 ... lag_decode_frame ... lagarith.c:574
```

The process may or may not crash depending on the surrounding memory layout, but ASAN will flag the out-of-bounds read.
