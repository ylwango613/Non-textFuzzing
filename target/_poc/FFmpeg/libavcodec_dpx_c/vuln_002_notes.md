# VULN 002 PoC Notes

## Vulnerability Summary

**Title**: Integer overflow in `dpx->stride` computation produces negative
`src_linesize` for `av_image_copy_plane`.

**File**: `libavcodec/dpx.c`  
**Function**: `decode_frame()` / `unpack_frame()`  
**Key lines**:
- Line 522: `dpx->stride = 4 * avctx->width * dpx->components;`
- Lines 629–644: size-check logic using the (possibly overflowed) stride
- Lines 211–213: `av_image_copy_plane()` called with `dpx->stride` as `src_linesize`

## Intended Trigger

With `descriptor=51` (RGBA, `components=4`), `bits_per_raw_sample=32`, and
`width=268435327`:

```
dpx->stride = 4 * 268435327 * 4 = 4,294,965,232
```

`4,294,965,232` overflows `INT_MAX` (2,147,483,647) and wraps to **-2064**
as a signed 32-bit integer.

The size check at line 630 then computes:

```
dpx->need_align * height + (int64_t)offset  >  avpkt->size
  -2064          *  2    + 2048             =  -2080  (always < avpkt->size)
```

So the negative stride **bypasses the guard** and reaches `unpack_frame()`,
where it is passed to `av_image_copy_plane()` as `src_linesize`, causing each
row to step backward by 2064 bytes in heap memory (heap OOB read).

## Critical Obstruction Found

Inspecting `libavcodec/dpx.c` line 369:

```c
if (avctx->bits_per_raw_sample > 31)
    return AVERROR_INVALIDDATA;
```

This guard executes **before** the stride computation switch-case at line 493.
Since `bits_per_raw_sample = 32 > 31`, `decode_frame()` returns
`AVERROR_INVALIDDATA` immediately, **never reaching** the stride calculation.

The `av_image_copy_plane()` path for bits=32 with elements>1 is also
**not taken** in `unpack_frame()`: when `elements=4`, the code goes to an
explicit pixel-by-pixel loop (lines 215–237) that does not use `dpx->stride`
at all. The `av_image_copy_plane()` call at line 211 is only reached when
`elements == 1`.

## Additional Concerns

1. **ff_set_dimensions rejection**: `av_image_check_size2` may reject
   `width=268435327, height=2` because `width * height = 536,870,654` exceeds
   `INT_MAX/8 = 268,435,455` (a common internal limit in FFmpeg), causing an
   early return before stride computation.

2. **ff_get_buffer failure**: Even if stride computation proceeds, allocating a
   frame of `268435327 × 2` pixels in GBRAPF32 format would require ~34 GB of
   memory, which will fail on any realistic system.

## PoC Approach

The PoC constructs a minimal DPX file (2064 bytes) with the trigger fields
set as described. Running it against the instrumented FFmpeg binary will show
which early-exit guard activates first.

## Expected Outcome

The binary is expected to return an error early — either from the
`bits_per_raw_sample > 31` guard or from `av_image_check_size2` — without
exercising the overflow path. **Status: UNVERIFIED** unless a variant of the
file bypasses all guards and produces a crash or ASAN report.
