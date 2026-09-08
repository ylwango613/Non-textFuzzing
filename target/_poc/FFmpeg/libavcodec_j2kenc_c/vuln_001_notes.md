# VULN 001 - Integer Overflow in JPEG2000 encoder encode_frame()

## Vulnerability

- **File**: `libavcodec/j2kenc.c`
- **Line**: 1482
- **CWE**: CWE-190 (Integer Overflow) → CWE-122 (Heap Buffer Overflow)
- **Build**: ASAN + UBSan (`-fsanitize=address,undefined`)

## Root Cause

In `encode_frame()`, the packet buffer size is computed as:

```c
avctx->width * avctx->height * 9 + FF_INPUT_BUFFER_MIN_SIZE
```

Both `avctx->width` and `avctx->height` are `int` (32-bit signed). The multiplication
`width * height * 9` is done in int32 precision. When the product exceeds INT32_MAX
(2,147,483,647), it overflows — UBSan catches this as signed integer overflow (CWE-190).

## Overflow Math

With width=15448, height=15448 (the PoC uses these dimensions):
- 15448 × 15448 = 238,640,704 pixels
- 238,640,704 × 9 = **2,147,766,336** > INT32_MAX = 2,147,483,647
- **UBSan fires**: `signed integer overflow: 238640704 * 9 cannot be represented in type 'int'`
- Wrapped int32 result: **-2,147,184,576** (negative)
- -2,147,184,576 + FF_INPUT_BUFFER_MIN_SIZE (16384) = **-2,147,168,192**
- ff_alloc_packet rejects negative size → encoding fails safely

## Two Overflow Scenarios

### Scenario 1 (Negative overflow, TRIGGERED in this PoC):
- Dimensions like 15448×15448 where width×height×9 ∈ (INT32_MAX, 2^32)
- Result wraps to **negative** int32
- ff_alloc_packet safely rejects negative size
- UBSan detects CWE-190 (integer overflow)
- Status: **VERIFIED_BEHAVIOR**

### Scenario 2 (Positive overflow, NOT triggerable via CLI):
- Dimensions like 30000×16000 where width×height×9 > 2^32
- Result wraps to a **small positive** int32 (~25MB)
- Allocation succeeds but buffer is far too small → HEAP BUFFER OVERFLOW
- FFmpeg's image size check **rejects these large dimensions** before reaching the encoder
- Status: theoretically causes CWE-122 but prevented by defensive checks

## PoC Approach

Instead of a disk file (which would need 228MB+ of pixel data), we use FFmpeg's
rawvideo demuxer with `/dev/zero` as the infinite zero-byte source:

```bash
ffmpeg -probesize 32 \
  -f rawvideo -video_size 15448x15448 -pixel_format gray8 -framerate 1 -i /dev/zero \
  -c:v jpeg2000 -tile_width 32768 -tile_height 32768 \
  -frames:v 1 -f null -
```

Key parameters:
- `video_size 15448x15448`: triggers int32 overflow (238.6M pixels × 9 > INT32_MAX)
- `pixel_format gray8`: smallest frame size (1 byte/pixel = 228MB frame)
- `tile_width/height 32768`: forces 1 large tile (faster JPEG2000 init, fewer malloc calls)
- `probesize 32`: minimal probing (faster startup)

## Expected UBSan Output

```
src/libavcodec/j2kenc.c:1482:70: runtime error: signed integer overflow: 238640704 * 9 cannot be represented in type 'int'
[jpeg2000 @ ...] Invalid minimum required packet size -2147184576 (max allowed is 2147483583)
```

## Files

- `vuln_001_gen.py` — generates a minimal 1×1 TIFF placeholder (not used for trigger)
- `vuln_001_run.sh` — triggers the vulnerability using rawvideo + /dev/zero
- `vuln_001_result.txt` — FFmpeg + UBSan output (shows integer overflow at j2kenc.c:1482)
- `vuln_001_status.txt` — PoC status: VERIFIED_BEHAVIOR

## Performance Note

The test requires ~55-60 seconds due to ASAN overhead initializing the JPEG2000 codec
for a 238M-pixel image (allocating wavelet coefficient structures). The 60-second timeout
in the prescribed test is therefore tight; the test passes when system load is low.
