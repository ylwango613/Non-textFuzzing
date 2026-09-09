# VULN 001 - SKIPPED: Integer Overflow in DEFLATE zbuf Allocation

## Vulnerability Summary

- **File**: `libavcodec/tiffenc.c`
- **Function**: `encode_frame()`
- **Lines**: 407-428
- **Root cause**: `zlen` (int) assigned the product `bytes_per_row * s->rps`, where the product is computed in int64_t space (because `bytes_per_row` is `int64_t`) but then truncated to `int`.

## Why SKIPPED

### Case 1: Negative zlen (product in range [2^31, 2^32-1])

When the product overflows the positive int32 range but stays below 2^32, `zlen` becomes a negative int. On 64-bit systems, `av_malloc(zlen)` receives a huge `size_t` value (approximately 2^32 - product, sign-extended to 64 bits), causing malloc to return NULL. This NULL is caught immediately:

```c
zbuf = av_malloc(zlen);
if (!zbuf) {
    ret = AVERROR(ENOMEM);
    goto fail;
}
```

Result: Safe failure with ENOMEM, no OOB write.

### Case 2: Small positive zlen (product >= 2^32 + 1)

For `zlen` to wrap to a small positive value, the product `bytes_per_row * height` must be at least 2^32 + 1 ≈ 4,294,967,297.

**Mathematical constraint**: `bytes_per_row` is capped at INT_MAX (2,147,483,647) by an explicit guard at lines 356-357. To achieve a product >= 4.3 billion with bytes_per_row <= ~2.1 billion:

- Minimum height to force overflow: 2 (giving product >= 4.3 billion only if bytes_per_row >= 2.15 billion)
- A bytes_per_row of ~2.15 billion requires a single row of ~2.15 billion bytes (e.g., ~716 million pixels at 3 bytes per pixel for RGB24).

**Total frame memory requirement**: `bytes_per_row * height >= 4.3 GB`. Since the loop at lines 418-427 then copies `bytes_per_row` bytes per row, the encoder must read that many bytes from the actual decoded frame. The input frame itself must contain >= 4.3 GB of pixel data.

This is infeasible because:
1. Most systems cannot allocate a single 4+ GB video frame.
2. Creating a crafted media file with a single 4+ GB frame payload is impractical for a standard PoC.
3. FFmpeg will fail to allocate the AVFrame data structures before reaching the TIFF encoder.

### Case 3: zlen = 0 (product exactly 2^32)

If the product is exactly 2^32, `zlen = 0`. `av_malloc(0)` implementation-defined behavior may return a non-NULL pointer to zero bytes, but the subsequent loop writing `bytes_per_row` bytes per row would immediately OOB. However, this case also requires a ~4 GB frame (same argument as Case 2).

## Conclusion

The vulnerability requires constructing a video frame with >= 4 GB of pixel data. This is not achievable via a crafted media file in a standard fuzzing/PoC scenario. The integer overflow exists in the code but is not practically exploitable as an external attack vector because the prerequisite frame dimensions trigger system memory exhaustion before the overflow site is reached.

Additionally, the negative-zlen path (smaller frames that still overflow int32) is safely caught by the NULL check on the av_malloc return value.
