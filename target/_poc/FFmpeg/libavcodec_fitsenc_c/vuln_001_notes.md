# VULN 001: FITS Encoder Integer Overflow in data_size

## Vulnerability Location
- **File**: `libavcodec/fitsenc.c`, line 80
- **Function**: `fits_encode_frame()`

## Root Cause

```c
// Line 80 - ALL OPERANDS ARE int (int32):
data_size = (bitpix >> 3) * avctx->height * avctx->width * naxis3;
```

The right-hand side is computed in **int32 arithmetic** before being assigned to `uint64_t data_size`. For large width/height values, the multiplication overflows int32 and wraps to a small positive value.

## Overflow Example (GRAY8, theoretical)

- `bitpix = 8`, `naxis3 = 1`
- `width = 65537`, `height = 65537`
- Correct value: `1 * 65537 * 65537 = 4,295,098,369` (exceeds INT32_MAX=2,147,483,647)
- int32 overflow result: `4,295,098,369 - 4,294,967,296 = 131,073`
- Buffer allocated: ~132,480 bytes
- Pixel copy loop writes: `65537 * 65537 = 4,295,098,369` bytes → heap buffer overflow

## Triggerability Analysis

### FFmpeg Frame Size Guard

FFmpeg's `av_image_check_size2` (in `libavutil/imgutils.c`) validates frame dimensions before any frame can be decoded or created:

```c
if (w==0 || h==0 || w > INT32_MAX || h > INT32_MAX || 
    stride >= INT_MAX || stride*(h + 128ULL) >= INT_MAX)
```

where `stride = 8*w + 1024` (bits, int64).

### Mathematical Bound

From expanding `(8w + 1024)(h + 128) < INT_MAX = 2^31 - 1`:

```
8wh + 1024w + 1024h + 131072 < 2^31 - 1
=> 8wh < 2^31 - 1 - 1024(w+h) - 131072 < 2^31 - 1
=> wh < (2^31 - 1) / 8 = 268,435,455
```

Therefore, the maximum `(bitpix/8) * w * h * naxis3` for each format is:

| Format     | Formula      | Max value      | INT_MAX       | Overflows? |
|------------|--------------|----------------|---------------|------------|
| GRAY8      | 1 * wh       | 268,435,455    | 2,147,483,647 | NO         |
| GRAY16BE   | 2 * wh       | 536,870,910    | 2,147,483,647 | NO         |
| GBRP       | 3 * wh       | 805,306,365    | 2,147,483,647 | NO         |
| GBRAP      | 4 * wh       | 1,073,741,820  | 2,147,483,647 | NO         |
| GBRP16BE   | 6 * wh       | 1,610,612,730  | 2,147,483,647 | NO         |
| GBRAP16BE  | 8 * wh       | 2,147,483,640  | 2,147,483,647 | NO (margin=7!) |

**Conclusion**: The `av_image_check_size` guard mathematically prevents the encoder's int32 overflow from being reached through standard ffmpeg pipeline. The closest format (GBRAP16BE) has only a margin of 7 before overflow.

## PoC Results

1. **Truncated FITS file (65537x65537)**: Rejected by decoder — "Invalid data found when processing input" (decoder checks all data is present in packet).
2. **lavfi color 65537x65537**: Rejected — "Picture size 65537x65537 is invalid" (av_image_check_size validation).
3. **lavfi color 46341x46341**: Same rejection.

## Vulnerability Status

**Code-level bug confirmed** — line 80 of `fitsenc.c` computes a potentially dangerous int32 product. The bug is real and would cause heap buffer overflow if dimensions like 65537x65537 were reached.

**Not exploitable via standard ffmpeg CLI** — the frame dimension validation (`av_image_check_size`) acts as an accidental guard: within valid frame dimensions, no supported pixel format can produce a product exceeding INT32_MAX on line 80.

**Exploitable in library context** — if FFmpeg is used as a library and `avctx->width`/`avctx->height` are set directly (bypassing `av_image_check_size`), the overflow is reachable.

## Recommended Fix

```c
// fitsenc.c line 80 - cast to int64_t before multiplication:
data_size = (int64_t)(bitpix >> 3) * avctx->height * avctx->width * naxis3;
```
