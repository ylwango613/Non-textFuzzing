# VULN 001 – Heap OOB Read in mjpega_dump_header BSF

## Vulnerability

**File**: `libavcodec/bsf/mjpega_dump_header.c`, line 76  
**Type**: Heap Out-of-Bounds Read (CWE-125)

The `mjpega_dump_header` bitstream filter scans an incoming MJPEG packet for
JPEG markers. The loop iterates while `i < in->size - 1`, so `i` can reach
`in->size - 2`. When the SOS marker (`0xFF 0xDA`) appears at exactly that
position (the last two bytes of the packet), the code on line 76 executes:

```c
bytestream_put_be32(&out_buf, i + 46 + AV_RB16(in->data + i + 2)); /* data off */
```

`in->data + i + 2` equals `in->data + in->size`, which is one byte past the
allocated buffer. `AV_RB16` then reads two bytes starting there — a 2-byte
heap OOB read. The value read from beyond the buffer is used as an offset
written into the output packet header, so it is not immediately discarded.

## PoC Structure

`vuln_001_gen.py` constructs a minimal MJPEG/JPEG byte sequence:

| Segment | Bytes | Purpose |
|---------|-------|---------|
| SOI     | FF D8 | JPEG start-of-image |
| APP0    | FF E0 + JFIF | FFmpeg MJPEG demuxer recognition |
| DQT     | FF DB | quantization table (required for SOF0) |
| SOF0    | FF C0 | baseline DCT frame header, 1×1 pixel |
| DHT     | FF C4 | Huffman table header (empty) |
| **SOS** | **FF DA** | **last two bytes — no length or scan data** |

Because the file has no EOI (`FF D9`), and the raw MJPEG demuxer consumes the
whole file as one packet, the resulting `AVPacket` ends with `FF DA`. The BSF
loop then hits `i == in->size - 2`, detects the SOS marker, and executes the
OOB read on line 76.

## Trigger Command

```bash
ffmpeg -f mjpeg -i vuln_001_input.mjpeg -bsf:v mjpegadump -f null -
```

## Expected Behavior with ASAN

An AddressSanitizer-instrumented build should report:
```
ERROR: AddressSanitizer: heap-buffer-overflow
READ of size 2 at 0x... (2 bytes past end of allocated region)
```
in `mjpega_dump_header_filter` (mjpega_dump_header.c:76).

## Impact

An attacker supplying a crafted MJPEG file can cause FFmpeg to read memory
beyond the allocated packet buffer. While this specific instance reads only 2
bytes, the value influences the output packet's "data offset" field, and in
other code paths such OOB reads can expose heap metadata or adjacent allocation
contents, potentially aiding further exploitation or causing instability.
