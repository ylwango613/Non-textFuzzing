# VULN 001: Integer Overflow in cfhd_encode_init() — PoC Notes

## Vulnerability

`libavcodec/cfhdenc.c` lines 278-301 compute:

```c
w8 = width / 8 + 64;      // +64 padding term
h8 = height / 8;
av_calloc(h8 * 8 * w8 * 8, sizeof(int16_t))  // int overflow here
```

For `width=65536, height=65536` (both multiples of 16):
- `w8 = 8192 + 64 = 8256`
- `h8 = 8192`
- True product: `8256 * 8192 * 64 = 4,329,447,424` (overflows int32 AND uint32)
- Wrapped int32 value: `33,554,432` (positive — passes NULL check!)
- `av_calloc(33554432, 2)` = **64 MB** (instead of the needed ~8.6 GB)

Subband pointer `subband[9]` is then set to `dwt_buf + 3*w2*h2` where `w2=33024, h2=32768`, giving an offset of ~3.2 billion int16_t elements — far past the 64 MB buffer. Writing through these pointers in `cfhd_encode_frame()` causes massive heap OOB write.

## Attempted Trigger Methods

### Attempt 1: Crafted AVI with Malformed Dimensions
- Generated `vuln_001_input.avi` (244 bytes) declaring `65536x65536`, BI_RGB, single 12-byte frame
- Result: **avformat_find_stream_info** tries to open the rawvideo decoder, which calls `av_image_check_size2()` and rejects the dimensions as invalid:
  ```
  [rawvideo] [IMGUTILS] Picture size 65536x65536 is invalid
  ```
- The CFHD encoder is **never initialized** (lazy-init waits for first valid frame)

### Attempt 2 & 3: lavfi Source at 65536x65536
- ffmpeg's `color` lavfi filter also calls imgutils and rejects the dimensions:
  ```
  [Parsed_color_0] [IMGUTILS] Picture size 65536x65536 is invalid
  ```

## Root Cause Analysis: Why CLI Trigger Fails

### Mathematical Contradiction
For `av_image_check_size2()` to pass (required for any frame to exist):
- `(8*w + 1024) * (h + 128) < INT_MAX` (using AV_PIX_FMT_NONE, 8 bits/pixel)
- Equivalent to: `(w + 128) * (h + 128) < ~2^28`

For cfhd_encode_init overflow to wrap positive (needed for underallocation):
- `(w/8 + 64) * (h/8) * 64 > 2^32`
- Equivalent to: `(w + 512) * h > ~2^35`

These two constraints are **mathematically contradictory**. Any dimensions that satisfy the cfhd overflow requirement exceed the imgutils limit by a factor of ~128x.

### Double Protection in avcodec_open2
Even if large dimensions somehow reached the encoder, `avcodec_open2()` in `libavcodec/avcodec.c` lines 241-246 explicitly calls `av_image_check_size2()` BEFORE calling `cfhd_encode_init()`, resetting invalid dimensions to 0×0. `cfhd_encode_init()` then returns `AVERROR_INVALIDDATA` at the height<32 check.

### Protection Layers (in order):
1. **Container demuxer** (AVI/etc.): calls `av_image_check_size2` during `find_stream_info`
2. **Filter graph** (lavfi/scale): validates frame dimensions via imgutils
3. **`avcodec_open2()`** (libavcodec/avcodec.c:241-246): validates `avctx->width/height` before calling `cfhd_encode_init()`
4. **`cfhd_encode_init()`** (cfhdenc.c:260-268): checks `height < 32` and `width & 15`

## Conclusion

The integer overflow exists in `cfhd_encode_init()` code (cfhdenc.c:286) and is a genuine CWE-190. However, it is **not exploitable through the ffmpeg CLI** because:
- The imgutils constraint makes it mathematically impossible to have valid dimensions that trigger the overflow
- `avcodec_open2()` adds a second check-and-reset before reaching `cfhd_encode_init()`

The vulnerability would only be exploitable by:
- A custom program that directly calls `cfhd_encode_init()` via the API and sets `avctx->width/height` after the `avcodec_open2()` size validation
- Or a build of FFmpeg compiled without the imgutils bounds checks (embedded/security-stripped build)
