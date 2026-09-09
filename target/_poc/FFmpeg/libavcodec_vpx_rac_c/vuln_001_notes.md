# PoC Notes: VULN 001 – ff_vpx_init_range_decoder OOB Read

## Vulnerability Summary

**File**: `libavcodec/vpx_rac.c`, lines 42-53  
**Function**: `ff_vpx_init_range_decoder()`  
**CWE**: CWE-125 (Out-of-bounds Read)

## Root Cause

The guard `if (buf_size < 1) return AVERROR_INVALIDDATA;` only rejects empty
buffers. However, the next line unconditionally calls
`bytestream_get_be24(&c->buffer)`, which reads **3 bytes**. When `buf_size` is
1 or 2, the check passes but the 3-byte read extends 1–2 bytes past the end of
the allocated buffer.

## Trigger Path

```
ffmpeg -i crafted.webm -f null -
  → vp8_decode_frame()
  → decode_frame_header()
  → ff_vpx_init_range_decoder(c, buf, header_size)
```

## Frame-tag Manipulation

A VP8 frame begins with a 3-byte little-endian tag. The decoder interprets it as:

- bit 0    : frame type (1 = inter/non-keyframe)
- bits 1-3 : profile
- bit 4    : show_frame
- bits 5-23: `header_size` (partition 0 size, computed as `AV_RL24(tag) >> 5`)

Crafted tag bytes: `[0x31, 0x00, 0x00]`

```
AV_RL24([0x31,0x00,0x00]) = 0x000031 = 49
bit 0 = 1  → inter frame  (avoids sync-code check)
bit 4 = 1  → show_frame   (frame is visible/decoded)
header_size = 49 >> 5 = 1
```

After consuming the 3-byte frame tag, the remaining buffer is 1 byte.
The size check `if (header_size > buf_size)` → `1 > 1` → **false** → passes.

`ff_vpx_init_range_decoder(c, buf, 1)` is called and
`bytestream_get_be24()` reads bytes at offsets +0, +1, +2 from a 1-byte buffer
→ **1–2 bytes of OOB read**.

## Generated Input

`vuln_001_input.webm` is a minimal WebM file containing:
- A valid EBML header (DocType=webm)
- A Segment with SegmentInfo, a Tracks element (V_VP8, 16×16 pixels)
- A single Cluster with one SimpleBlock carrying the 4-byte VP8 payload
  `[0x31, 0x00, 0x00, 0x00]`

## Expected ASAN Output

With an AddressSanitizer-instrumented build the run should produce something
similar to:

```
==PID==ERROR: AddressSanitizer: heap-buffer-overflow on address ...
READ of size 1 at offset 1 ...
  #0 bytestream_get_be24 ... vpx_rac.c:51
  #1 ff_vpx_init_range_decoder ... vpx_rac.c:51
  #2 decode_frame_header ... vp8.c:...
  #3 vp8_decode_frame ... vp8.c:...
```

Without ASAN the decoder may silently read garbage values, potentially leading
to mis-decoding or further downstream issues.
