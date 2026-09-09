# VULN 001 – Integer Overflow in five_planes Allocation (PHOTOMETRIC_SEPARATED TIFF)

## Summary

**Status: UNVERIFIED**

The vulnerability exists as a latent integer overflow in
`libavcodec/tiff.c:decode_frame()` at lines 2215–2219, but a pre-existing
dimension-validity guard prevents the crafted input from reaching the vulnerable
computation at runtime.

## Vulnerability Details

**Location:** `libavcodec/tiff.c`, function `decode_frame()`, lines 2215–2219

```c
stride = p->linesize[plane];
if (s->photometric == TIFF_PHOTOMETRIC_SEPARATED &&
    s->avctx->pix_fmt == AV_PIX_FMT_RGBA) {
    stride = stride * 5 / 4;           // <-- signed integer overflow (UB)
    five_planes =
    dst = av_malloc(stride * s->height);  // <-- heap under-allocation
    if (!dst)
        return AVERROR(ENOMEM);
}
```

**Pixel format selection** (`init_image`, `tiff.c:1059`):

```c
switch (s->planar * 10000 + s->bpp * 10 + s->bppcount + s->is_bayer * 100000)
// For planar=0, bpp=40 (8*5), bppcount=5, is_bayer=0:
//   0 + 40*10 + 5 = 405
case 405:
    if (s->photometric == TIFF_PHOTOMETRIC_SEPARATED)
        s->avctx->pix_fmt = AV_PIX_FMT_RGBA;
```

**TIFF tags required to reach case 405:**
- SamplesPerPixel (277) = 5
- BitsPerSample (258) = [8, 8, 8, 8, 8]
- PhotometricInterpretation (262) = 5 (PHOTOMETRIC_SEPARATED)

## Trigger Conditions and Overflow Math

For `stride * 5` to overflow `int32`:

```
stride = p->linesize[0] = FFALIGN(width * 4, 32)
stride * 5 > INT32_MAX = 2,147,483,647
FFALIGN(width * 4, 32) > 429,496,729
width > 107,374,182
```

With `width = 107,374,182`:
- `linesize[0] = FFALIGN(429496728, 32) = 429496736`
- `429496736 * 5 = 2,147,483,680 > INT32_MAX` → **signed integer overflow (UB)**
- Wrapped result: `-2,147,483,616` (as int32)
- After `/ 4`: `-536,870,904` (negative stride)
- `av_malloc(-536870904 * 4)` → size_t = 18446744071562067680 → ENOMEM

With specially crafted `width = 214,748,368` (wraps to small positive stride):
- `linesize[0] = FFALIGN(858993472, 32) = 858993472`
- `858993472 * 5 = 4,294,967,360` → wraps to 64 (int32)
- `64 / 4 = 16` → `av_malloc(16 * height)` → tiny 64-byte buffer
- Width × 5 channels of strip data written into 64-byte buffer → **heap-buffer-overflow**

## Why the PoC Did Not Trigger

`av_image_check_size2` (libavutil/imgutils.c:289) rejects the image before frame
allocation with this check:

```c
int64_t stride = av_image_get_linesize(pix_fmt, w, 0);
stride += 128 * 8;
if (stride * (h + 128ULL) >= INT_MAX) {
    // "Picture size %ux%u is invalid"
    return AVERROR(EINVAL);
}
```

For `AV_PIX_FMT_RGBA, w=107374182, h=4`:
- `av_image_get_linesize = 429496728`
- `stride_check = 429496728 + 1024 = 429497752`
- `429497752 * (4 + 128) = 56,693,703,264 ≥ INT_MAX` → **rejected**

The minimum width required to overflow `stride * 5` (>107M pixels) produces a
`stride_check * (h + 128)` value that is **~26× INT_MAX** for any valid `h ≥ 1`.
There is no valid width for `AV_PIX_FMT_RGBA` that simultaneously:
1. Passes `av_image_check_size2`
2. Causes `linesize[0] * 5` to overflow `int32`

## Actual Runtime Output

```
[tiff @ ...] [IMGUTILS @ ...] Picture size 107374182x4 is invalid
[dec:tiff @ ...] Decoding error: Invalid argument
```

No ASAN heap-buffer-overflow or UBSAN signed-integer-overflow was reported because
the vulnerable lines were never executed.

## Crafted TIFF Structure

The generated file (`vuln_001_input.tiff`, 148 bytes) is a valid little-endian TIFF:

| Field                      | Value                              |
|----------------------------|------------------------------------|
| Byte order                 | Little-endian (II)                 |
| Magic                      | 42 (0x002A)                        |
| ImageWidth                 | 107,374,182                        |
| ImageLength (height)       | 4                                  |
| BitsPerSample              | [8, 8, 8, 8, 8]                    |
| Compression                | 1 (TIFF_RAW, uncompressed)         |
| PhotometricInterpretation  | 5 (PHOTOMETRIC_SEPARATED / CMYK+) |
| SamplesPerPixel            | 5                                  |
| RowsPerStrip               | 4                                  |
| StripByteCounts            | 4                                  |
| ExtraSamples               | 0 (unspecified)                    |
| Strip data                 | 4 × 0x00 bytes                    |

## Conclusion

The integer overflow vulnerability at `tiff.c:2215-2219` is real (latent UB in C
per the C standard), but it is mitigated by the pre-existing dimension check in
`av_image_check_size2`. The code defect would be exploitable on a hypothetical build
or runtime environment where:
- The dimension check is bypassed or absent, OR
- The frame buffer is allocated via a path that skips `av_image_check_size2`

The vulnerability should still be patched (e.g., by using signed-overflow-safe
arithmetic or an explicit check `if (stride > INT_MAX / 5)`) to eliminate the
undefined behavior.
