# VULN-001 PoC Notes: decode_mous Integer Overflow → draw_cursor OOB Read

## Vulnerability Summary

In `rasc.c` `decode_mous()` (line 569):

```c
if (uncompressed_size != 3 * w * h)   // unsigned 32-bit arithmetic
    return AVERROR_INVALIDDATA;
```

With `w=32100` and `h=44600`, the multiplication `3 * 32100 * 44600 = 4,294,980,000`
overflows a 32-bit unsigned integer (wraps to 12704). An attacker sets
`uncompressed_size=12704`, bypassing the check. `av_fast_padded_malloc` then allocates
only ~12768 bytes for `s->cursor`, but `cursor_w=32100` and `cursor_h=44600` are stored.

In `draw_cursor()` (PAL8 path), the index expression:

```c
s->cursor[3 * s->cursor_w * (s->cursor_h - i - 1) + 3 * j + 0]
```

reaches a maximum of `3 * 32100 * 44599 ≈ 4,294,883,700`, causing a massive heap OOB
read (ASAN: heap-buffer-overflow).

## PoC Approach

The AVI container wraps a single RASC packet containing:
1. **FINT(100×100, PAL8)** — small valid dimensions to initialize frame1/frame2 and set
   `avctx->pix_fmt = AV_PIX_FMT_PAL8`.
2. **FINT(32100×44600, PAL8)** — large dimensions to set `avctx->width/height` for the
   MOUS dimension check to pass.
3. **MOUS(w=32100, h=44600, uncompressed_size=12704)** — triggers the overflow; cursor
   buffer allocated with 12704 bytes.
4. **MPOS(0, 0)** — positions the cursor at origin so `draw_cursor`'s early-return bounds
   check passes (cursor_x + cursor_w ≤ avctx->width).

## Why the PoC Does Not Produce a Verified Crash in This Build

`ff_set_dimensions()` in `libavcodec/utils.c` calls:

```c
av_image_check_size2(width, height, s->max_pixels, AV_PIX_FMT_NONE, 0, s);
```

The check (in `libavutil/imgutils.c`) estimates stride **always** as `8 * w` (because
`AV_PIX_FMT_NONE` produces an invalid linesize, triggering the `8LL*w` fallback):

```c
int64_t stride = av_image_get_linesize(pix_fmt, w, 0);  // ≤0 for NONE
if (stride <= 0) stride = 8LL * w;
stride += 128 * 8;  // 1024

if (stride * (h + 128ULL) >= INT_MAX) { ... fail ... }
```

For `w=32100, h=44600`:

    stride = 8 * 32100 + 1024 = 257,824
    257,824 × (44600 + 128) = 11,531,951,872  >>  INT_MAX (2,147,483,647)  → REJECTED

The same `AV_PIX_FMT_NONE` check also appears in `ff_get_buffer()` (`decode.c:1787`),
so even if `ff_set_dimensions` were bypassed, frame allocation would also fail.

**The minimum product `w × h` required for `3wh` to overflow 32 bits is ≈1.43 billion,
which always yields `stride × (h+128) > INT_MAX`. The constraints are mathematically
incompatible in this FFmpeg version.**

To exploit this in practice would require either:
- An FFmpeg version where `ff_set_dimensions` uses the actual pixel-format stride
  (e.g., 1 byte/pixel for PAL8 → `stride=32100+1024=33124`, check = 1.48B < INT_MAX ✓),
  or
- A build where the stride over-estimate constant is removed from `av_image_check_size2`.

The vulnerability **code** (the `3 * w * h` overflow in `decode_mous`, and the unchecked
index in `draw_cursor`) is genuine and present in this source tree. The size-check in
`ff_set_dimensions` acts as a de-facto mitigating barrier in this specific binary.
