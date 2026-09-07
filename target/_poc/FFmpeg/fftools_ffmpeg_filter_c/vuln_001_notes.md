# VULN 001 PoC Notes

## Vulnerability
Integer overflow in `sub2video_copy_rect()` bounds check (ffmpeg_filter.c:319)
- `r->x + r->w > w` uses signed int addition without overflow protection
- If r->x near INT_MAX, r->x + r->w overflows to negative, bypassing the check
- Subsequent `dst += r->x * 4` also overflows, enabling OOB heap write

## PoC Approach
- Crafted MKV with PGS (HDMV/PGS) bitmap subtitle track (S_HDMV/PGS)
- Video track: 320x240 MJPEG, 25fps
- Subtitle rectangles with coordinates set to maximum achievable 16-bit values (x=65000, y=65000)
- ffmpeg invoked with `-filter_complex '[0:v][0:s]overlay'` to force the sub2video path

## Trigger Path
ffmpeg -i vuln_001_input.mkv -filter_complex '[0:v][0:s]overlay' -f null -
→ sub2video canvas configured (320x240)
→ sub2video_update() called on subtitle packet
→ sub2video_copy_rect() called for each subtitle rect

## Expected Phenomenon
- If r->x near INT_MAX: bounds check bypassed → OOB heap write → ASAN heap-buffer-overflow
- With 16-bit coordinates (max 65535): bounds check logs warning and returns early

## Actual Result
- sub2video code path confirmed reachable (canvas created, subtitle decoded)
- No ASAN crash because 16-bit coordinates cannot trigger the signed integer overflow
- The check at line 319 correctly catches the out-of-bounds coords and returns

## Why Not Triggered
Standard subtitle formats (PGS, DVB, DVDSUB, XSUB) all use 16-bit coordinate fields (max 65535).
The signed overflow requires r->x >= 536,870,912 (2^29), which no standard format can produce.
The vulnerability is real but requires a subtitle decoder that emits 32-bit coordinates without validation.
