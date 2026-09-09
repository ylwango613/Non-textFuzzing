# VULN 001 Notes: Integer Overflow in v210enc stride Computation

## Status: SKIPPED

## Vulnerability Summary

- **File**: `libavcodec/v210enc.c` lines 72-78 (and `v210_template.c` lines 29-47)
- **Root cause**: `int stride = aligned_width * 8 / 3` uses 32-bit signed arithmetic.
  With `width=536870929`:
  - `aligned_width = ((536870929+47)/48)*48 = 536870976`
  - `536870976 * 8 = 4294967808` overflows `INT_MAX=2147483647`, wraps to 512
  - `stride = 512 / 3 = 170`
  - `ff_get_encode_buffer` allocates only 170 bytes
  - `pack_line()` writes ~1.4 GB into a 170-byte buffer → heap buffer overflow

## Why SKIPPED

The vulnerability **cannot be triggered by passing a crafted media file to the ffmpeg command line** because `av_image_check_size` is called in every input code path before `width=536870929` can reach the encoder.

### The blocking check

In `libavutil/imgutils.c`, `av_image_check_size2()`:

```c
int64_t stride = av_image_get_linesize(pix_fmt, w, 0);
if (stride <= 0)
    stride = 8LL*w;
stride += 128*8;

if (w==0 || h==0 || w > INT32_MAX || h > INT32_MAX || stride >= INT_MAX || ...) {
    av_log(..., "Picture size %ux%u is invalid\n", w, h);
    return AVERROR(EINVAL);
}
```

With `w=536870929` and `pix_fmt=NONE` (as called from `av_image_check_size`):
- `stride = 8LL * 536870929 = 4,294,967,432`
- `stride += 128*8 = 4,294,968,456`
- `stride >= INT_MAX` → `4,294,968,456 >= 2,147,483,647` → **TRUE → REJECTED**

This check fires before any decoder or filter can produce a frame.

### Approaches attempted (all blocked)

1. **Y4M sparse file** (`-i vuln_001_input.y4m`):
   - `yuv4mpegdec.c` line 257: calls `av_image_get_buffer_size()` → calls `av_image_check_size()` → FAIL
   - FFmpeg output: `[IMGUTILS] Picture size 536870929x1 is invalid`

2. **lavfi nullsrc** (`-f lavfi -i "nullsrc=size=536870929x1:rate=1"`):
   - `vsrc_testsrc.c` line 269: calls `av_image_check_size()` directly → FAIL
   - FFmpeg output: `[IMGUTILS] Picture size 536870929x1 is invalid`

3. **rawvideo pipe** (`-f rawvideo -video_size 536870929x1`):
   - `rawvideodec.c` line 73: calls `av_image_check_size()` directly → FAIL
   - FFmpeg output: `[IMGUTILS] Picture size 536870929x1 is invalid`

All three approaches also checked by `rawdec.c` line 238: `av_image_check_size()` in `raw_decode()`, and by `av_frame_get_buffer()` in `frame.c` line 86: `av_image_check_size()`.

### Why ff_get_encode_buffer does NOT protect

The encoder's `ff_get_encode_buffer(avctx, pkt, size=170, 0)` only checks:
```c
if (size < 0 || size > INT_MAX - AV_INPUT_BUFFER_PADDING_SIZE)
    return AVERROR(EINVAL);
```

Since `170 >= 0`, this passes and allocates 170 bytes. The overflow would then occur in `pack_line()`. However, no input path can deliver a frame with `width=536870929` to the encoder.

## Conclusion

The vulnerability is real and would cause a heap buffer overflow if exploited. However, `av_image_check_size` in `libavutil/imgutils.c` acts as a global gate that rejects any frame dimensions large enough to trigger the overflow. Since every demuxer, decoder, and filter that could supply input to the v210 encoder calls this check, the vulnerability cannot be exercised via the ffmpeg command line.
