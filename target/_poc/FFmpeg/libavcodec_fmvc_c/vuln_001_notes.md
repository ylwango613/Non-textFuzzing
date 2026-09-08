# VULN 001 – FMVC Heap OOB Write (CWE-190 → CWE-787): PoC Notes

## Status: UNVERIFIED

The vulnerability code path exists in `fmvc.c` but is blocked by a framework-level defense-in-depth guard before the vulnerable code is ever reached via the standard FFmpeg pipeline.

---

## Vulnerability Summary

**File**: `libavcodec/fmvc.c`

**Root cause (CWE-190 – Integer Overflow)**:
`decode_init()` line 616:
```c
s->buffer_size = avctx->width * avctx->height * 4;
```
With `width=32768`, `height=32769`, `biBitCount=32`, the 32-bit signed multiplication
`32768 * 32769 * 4 = 4,295,098,368` overflows `int32` (wraps to `131072` under `-fwrapv`).
`av_mallocz(131072)` allocates only 128 KB instead of ~4 GB.

**Trigger (CWE-787 – OOB Write)**:
`decode_frame()` lines 505–511 (P-frame XOR loop):
```c
for (k = 0; k < block_h; k++) {
    uint32_t *column = dst;
    for (l = 0; l < block_w; l++)
        *dst++ ^= *src++;         // LINE 509 – OOB WRITE
    dst = &column[s->stride];     // advances by stride=32768 DWORDs = 131072 bytes
}
```
After row `k=0` of block 0 (w=84, h=112): `dst` advances by `stride*4 = 131072` bytes,
exactly equaling the entire 128 KB buffer. Row `k=1` writes to `s->buffer + 131072`,
one byte past the allocation.

---

## PoC Approach

The generator (`vuln_001_gen.py`) builds a valid AVI/RIFF file:

- `BITMAPINFOHEADER`: `biWidth=32768`, `biHeight=32769`, `biBitCount=32`, `biCompression='FMVC'`
- A single P-frame (non-keyframe) video chunk (`00dc`) carrying:
  - Frame header: `skip=0, key_frame=0, nb_blocks=1, type=1, offset=0`
  - Compressed data using `decode_type1` encoding that decompresses to exactly
    `9408 × 4 = 37632` bytes (= `blocks[0].size * 4`), passing the size validation check
  - Encoding: `73 × [0x00 0xF9 + 512 zero bytes] + [0x00 0xE0 + 256 zero bytes] + [0x20 terminator]`
    → 37781 bytes compressed → 37632 bytes decompressed

With `blocks[0].xor = 1`, the XOR loop writes OOB at row `k=1`.

---

## Why the PoC Does Not Produce a Crash

### Framework Guard in `libavcodec/avcodec.c` lines 241–246:

```c
if ((avctx->coded_width || avctx->coded_height || avctx->width || avctx->height)
    && (av_image_check_size2(avctx->coded_width, avctx->coded_height, avctx->max_pixels, ...) < 0
     || av_image_check_size2(avctx->width, avctx->height, avctx->max_pixels, ...) < 0)) {
    av_log(avctx, AV_LOG_WARNING, "Ignoring invalid width/height values\n");
    ff_set_dimensions(avctx, 0, 0);   // resets width=height=0
}
```

This check fires BEFORE `decode_init()` is called during `avcodec_open2`.

### `av_image_check_size2` (imgutils.c line 301):

```c
if (stride*(h + 128ULL) >= INT_MAX) { ... return AVERROR(EINVAL); }
```

For `AV_PIX_FMT_NONE` (used here): `stride = 8*w + 1024 = 8*32768 + 1024 = 263168`.
`263168 × (32769 + 128) = 263168 × 32897 ≈ 8.66 × 10^9 >> INT_MAX = 2,147,483,647`.

**This check is mathematically impossible to satisfy simultaneously with the buffer overflow condition:**
- Overflow requires `w × h > 536,870,912`
- Check requires `(8w+1024) × (h+128) < 2,147,483,647`
- For any valid (w,h) satisfying the second inequality: `w×h << 536M`
- These conditions are mutually exclusive for all bpp values (16/24/32)

### Actual execution path:

1. `avcodec_open2` → `av_image_check_size2(32768, 32769, ...)` → logs "Picture size 32768x32769 is invalid" → resets `width=height=0`
2. `decode_init(width=0, height=0)` → `s->nb_blocks = 0` → returns `AVERROR_INVALIDDATA`
3. "Failed to open codec" — codec open fails; `decode_frame()` is **never called**
4. The vulnerable `s->buffer_size = width * height * 4` calculation on line 616 is **never executed** with overflow-triggering dimensions

---

## Conclusion

The integer overflow vulnerability EXISTS at the source-code level in `fmvc.c` and would lead to a heap OOB write if the decoder were invoked with the specified dimensions. However, the FFmpeg framework's dimension validation in `avcodec.c` (a separate, independent guard) prevents the vulnerable code from being reached through the standard `ffmpeg` command pipeline. The vulnerability requires exploiting the fmvc decoder through a path that bypasses the framework guard (e.g., a custom harness calling `avcodec_open2` with pre-validated dimensions, or an older FFmpeg build lacking the guard).

The crafted AVI file and frame-data encoding in this PoC are correctly constructed and would trigger the OOB write if the framework guard were absent.
