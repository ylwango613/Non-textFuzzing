# Vulnerability 001 — Skip Rationale

## Vulnerability Description

**Location:** `wbmp_encode_frame()` in `libavcodec/wbmpenc.c`, lines 53–70

**Root Cause:** The size calculation:

```c
int64_t size = avctx->height * ((avctx->width + 7) / 8) + 32;
```

Both `avctx->height` and the result of `((avctx->width + 7) / 8)` are `int` (32-bit signed). The multiplication is performed in 32-bit arithmetic before the result is widened to `int64_t`, so a sufficiently large product wraps silently to a small positive value. The subsequent `av_fast_padded_malloc` call would then allocate a small buffer while later code writes the full-sized bitmap data, constituting a heap buffer overflow.

## Why the Overflow Cannot Be Triggered via Standard FFmpeg Input

### Overflow Condition

For the 32-bit multiplication to overflow (wrap to a small positive value):

```
height * wpad > INT_MAX   where wpad = (width + 7) / 8
```

Substituting the definition of `wpad`:

```
height * width > 8 * INT_MAX ≈ 8 * 2,147,483,647 ≈ 17.2 billion
```

### av_image_check_size Constraint

`av_image_check_size` (called from `ff_set_dimensions`, which is invoked during frame setup for all decoded frames and most encoder initialization paths) enforces:

```
width * height <= max_pixels   (default: INT_MAX ≈ 2,147,483,647)
```

Any image whose `width * height` exceeds `INT_MAX` is rejected with an error before encoding begins.

### Mutual Exclusivity

- The overflow requires: `height * width > 17.2 billion`
- The size check allows: `height * width <= 2.1 billion`

These two conditions cannot be simultaneously satisfied. No input that passes `av_image_check_size` can have dimensions large enough to trigger the integer overflow.

### Input Paths Considered

The following standard FFmpeg input paths all go through `av_image_check_size` or equivalent validation and are therefore protected:

- Decoded media files (`ffmpeg -i <file> output.wbmp`)
- Raw video input (`ffmpeg -f rawvideo -s WxH ...`)
- Synthetic sources (`ffmpeg -f lavfi -i color=size=WxH ...`)
- Image format decoders (PNG, JPEG, BMP, etc.)

### Reachability

The vulnerability is only reachable by calling the WBMP encoder directly via the C API while manually constructing an `AVCodecContext` with oversized dimensions, bypassing `av_image_check_size`. This is not achievable through any standard media file or command-line invocation of `ffmpeg`.

## Conclusion

Because the overflow precondition and the upstream size validation are mutually exclusive, this vulnerability cannot be triggered via `ffmpeg -i <crafted_file> output.wbmp` or any other standard input path. The vulnerability is skipped.
