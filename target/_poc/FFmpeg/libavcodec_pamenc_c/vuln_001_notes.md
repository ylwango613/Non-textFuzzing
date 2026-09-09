# Vuln 001: PAM Encoder Integer Overflow → Heap Buffer Overflow

## Summary
- **File**: `libavcodec/pamenc.c`
- **Function**: `pam_encode_frame()`
- **Line**: 102
- **Type**: CWE-190 (Integer Overflow) → CWE-122 (Heap-Based Buffer Overflow)
- **Build tested**: ASAN+UBSAN (`-fsanitize=address,undefined`)

## Vulnerability Code (confirmed)

```c
// pamenc.c line 88-92 (for AV_PIX_FMT_RGBA64BE):
n = w * 8;           // w=16384 → n=131072

// pamenc.c line 102:
ff_get_encode_buffer(avctx, pkt, n*h + header_size, 0)
// n*h = 131072 * 32769 = 4,295,098,368 → int32 overflow to +131072
// Buffer allocated: ~131147 bytes
// Loop (lines 120-125) runs h=32769 iterations of memcpy(..., n=131072)
// Row 1 writes 131072 bytes past the ~131147-byte buffer → heap overflow
```

## PoC Approach

### Attempt 1: RGBA64BE TIFF (w=16384, h=32769)
Generated a big-endian TIFF with ImageWidth=16384, ImageLength=32769,
BitsPerSample=[16,16,16,16], SamplesPerPixel=4 (RGBA). Used RowsPerStrip=1
with 32769 strips; strips 0 and 1 have 131072 bytes of pixel data; strips
2+ have StripByteCounts=0 to break the decoder loop after 2 rows.

**Blocked by**: `av_image_check_size2` inside `ff_set_dimensions`
(tiff.c line 1225). With pix_fmt=`AV_PIX_FMT_NONE`, stride = 8×w = 131072,
then (131072+1024)×(32769+128) = 4,345,349,120 ≥ INT_MAX → `AVERROR(EINVAL)`.
TIFF decoder returns error; pam_encode_frame is never called.

### Attempt 2: MONOBLACK TIFF (w=16384, h=262144)
For `AV_PIX_FMT_MONOBLACK`: n = w = 16384. n×h = 16384×262144 = 2^32
→ int32 wraps to 0. The actual frame linesize is (w+7)/8 = 2048 bytes/row.
Generated big-endian TIFF with PhotometricInterp=1 (BlackIsZero), BPS=1,
SPP=1, RowsPerStrip=1, 262144 strips (2 real data, rest zero-count).

av_image_check_size2 with MONOBLACK pix_fmt would pass:
  stride=(16384+7)/8=2048, (2048+1024)×(262144+128) = 806M < INT_MAX ✓

**Blocked by**: `ff_set_dimensions` still calls `av_image_check_size2`
with `AV_PIX_FMT_NONE` (not the decoder's pix_fmt), so stride = 8×16384 = 131072.
(131072+1024)×(262144+128) >> INT_MAX → fails.

### Attempt 3: rawvideo demuxer (RGBA64BE, 16384×32769)
`ffmpeg -f rawvideo -pixel_format rgba64be -video_size 16384x32769 -i /dev/zero ...`

**Blocked by**: rawvideo demuxer calls `av_image_check_size` before opening.
Same stride check with NONE pix_fmt fails immediately.

## Root Cause of Failure to Trigger

The protection is in `ff_set_dimensions` (libavcodec/utils.c line 93):

```c
int ret = av_image_check_size2(width, height,
                               s->max_pixels,
                               AV_PIX_FMT_NONE,   // ← NOT actual pix_fmt
                               0, s);
```

With `AV_PIX_FMT_NONE`, `av_image_get_linesize` returns ≤ 0, so the
fallback stride = `8 × w` (worst-case 8 bytes/pixel assumption).

**Proof of impossibility**: For any PAM-supported pixel format,
`n ≤ 8×w` (RGBA64BE has n = 8w, the maximum). If n×h > INT_MAX
(triggering the overflow), then `(8×w+1024)×(h+128) ≥ n×h > INT_MAX`
→ the stride check always fails. It is mathematically impossible for a
frame that passes `ff_set_dimensions` to also trigger the `n×h` overflow
in `pam_encode_frame`.

## Conclusion

The vulnerability is **confirmed present in the code** (pamenc.c line 102:
`n*h + header_size` computed as int32 with no overflow guard), but is
**unreachable through any standard ffmpeg decode+encode pipeline** because:

1. Every decoder calls `ff_set_dimensions`, which uses AV_PIX_FMT_NONE
   stride (8×w), guaranteeing that n×h < INT_MAX for any accepted frame.
2. The encoder's `avcodec_open2` also calls `av_image_check_size2` with
   the same worst-case stride.
3. All demuxers (rawvideo, lavfi, etc.) apply the same check.

The overflow would be exploitable via **direct libavcodec API usage**
where an application creates an `AVFrame` with oversized dimensions
(bypassing the standard size checks) and passes it directly to the PAM
encoder. This is not achievable via a crafted media file alone.

## Files Generated
- `vuln_001_gen.py`: Generates the TIFF PoC input
- `vuln_001_input.tiff`: Crafted TIFF (384 KB → later regenerated as 2MB MONOBLACK version)
- `vuln_001_run.sh`: Shell script to run the attempt
