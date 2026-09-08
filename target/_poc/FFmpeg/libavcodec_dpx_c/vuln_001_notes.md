# VULN 001 - DPX Integer Overflow: Size Check Bypass → Heap OOB Read

## File: libavcodec/dpx.c, decode_frame()

## Vulnerability Summary

An integer overflow in the pixel-data size check at line 629–630 of `dpx.c` allows the
bounds guard to be bypassed, leading to `unpack_frame()` performing a heap out-of-bounds
read far beyond the end of the input packet buffer.

### Root Cause

```c
// Line 629
dpx->need_align = FFALIGN(dpx->stride, 4);
// Line 630 — VULNERABLE: int * int multiplication before int64_t promotion
if (dpx->need_align*avctx->height + (int64_t)offset > avpkt->size && ...)
```

Both `dpx->need_align` and `avctx->height` are `int`. Their product is computed as
signed 32-bit integer arithmetic **before** promotion to `int64_t`. When:

  stride = 2 * 2048 * 4 = 16384  (16-bit RGBA, width=2048)
  need_align = FFALIGN(16384, 4) = 16384
  16384 * 131072 = 2^31 = 2,147,483,648

This value overflows `int32_t` to `-2,147,483,648` (INT_MIN). After promotion:

  (int64_t)(-2147483648) + 2048 = -2147481600

Since `-2147481600 > avpkt->size (4096)` is **FALSE**, the safety check is bypassed.

### Effect

The `else` branch is taken (lines 641–643):
  - `need_align -= stride` → 16384 - 16384 = 0
  - `stride = FFALIGN(16384, 4) = 16384`

`unpack_frame()` is then called (via `av_image_copy_plane`) and attempts to read
`stride × height = 16384 × 131072 ≈ 2 GB` bytes starting from `avpkt->data + offset`,
while the actual buffer is only ~2048 bytes beyond `offset`. This causes a heap OOB read.

## Note on bits_per_raw_sample=32

The vulnerability report mentions `bits_per_raw_sample=32`. However, the current source
has a guard at line 369:
  `if (avctx->bits_per_raw_sample > 31) return AVERROR_INVALIDDATA;`

This guard blocks the 32-bit code path. The same overflow is achieved with **bits=16** and
**height=131072**, which also gives `stride * height = 2^31`.

## PoC Parameters

| Field       | Value    | Why                                      |
|-------------|----------|------------------------------------------|
| Magic       | SDPX     | Big-endian DPX                           |
| Width       | 2048     | stride = 2×2048×4 = 16384               |
| Height      | 131072   | 16384 × 131072 = 2^31 → int32 overflow  |
| Descriptor  | 51       | RGBA, 4 components                       |
| Bit size    | 16       | → pix_fmt RGBA64BE (case 51161)          |
| Image offset| 2048     | Must be < file size for validity check   |
| File size   | 4096 B   | Tiny; only ~2KB of "pixel" data          |

## Expected Behavior

- With ASAN: **heap-buffer-overflow** in `unpack_frame()` / `av_image_copy_plane()`,
  reading past the end of `avpkt->data`.
- Without ASAN: likely segfault or silent memory corruption.
- If `ff_get_buffer()` fails (allocation of ~2GB output frame refused by OS):
  function returns AVERROR(ENOMEM) before reaching `unpack_frame()` → VERIFIED_BEHAVIOR.

## Attack Vector

`ffmpeg -i crafted.dpx -f null -`
