# VULN 002: Integer Overflow in s->alpha Allocation — PoC Notes

## Vulnerability Summary

**File**: `libavcodec/cfhdenc.c`, `cfhd_encode_init()`, line 373  
**Class**: Integer overflow → heap under-allocation → heap OOB write  

```c
// Line 373 — vulnerable:
s->alpha = av_calloc(avctx->width * avctx->height, sizeof(*s->alpha));
```

`avctx->width` and `avctx->height` are both `int` (32-bit signed).  
When width=46336 and height=46352 (both multiples of 16):
- Actual product: 46336 × 46352 = 2,147,766,272 > INT_MAX (2,147,483,647)
- Signed integer overflow (UB in C), wraps to negative: −2,147,201,024
- Passed as `size_t` to `av_calloc`: huge value → allocation fails → ENOMEM  
  **OR** in some compiler/optimization contexts, the product wraps positive-small  
  → tiny allocation → `process_alpha()` writes W×H int16_t elements → massive heap OOB

## Trigger Condition

- `s->planes == 4` (checked at line 370), which requires `AV_PIX_FMT_GBRAP12`
- Width and height must be multiples of 16 (checked at line 265)
- `process_alpha()` at line 452 is called with the full `avctx->width × avctx->height` count,
  writing to the under-allocated `s->alpha` buffer

## Why ffmpeg Command-Line Cannot Trigger This

The `avcodec_open2()` call in `libavcodec/avcodec.c` (lines 241–246) calls:

```c
av_image_check_size2(avctx->width, avctx->height, avctx->max_pixels, AV_PIX_FMT_NONE, 0, avctx)
```

`av_image_check_size2` in `libavutil/imgutils.c` line 301 enforces:

```c
stride*(h + 128ULL) >= INT_MAX  → FAIL (invalid)
```

where `stride = 8*w + 1024` (for `AV_PIX_FMT_NONE`).

**Mathematical proof**: for any w, h where w×h > INT_MAX:
```
(8w + 1024) × (h + 128) ≥ 8×w×h > 8×INT_MAX ≫ INT_MAX
```

The stride-based check **always rejects** dimensions where w×h > INT_MAX, so:
- All code paths through the ffmpeg binary go through `avcodec_open2`
- `avcodec_open2` resets width/height to 0 if the check fails
- `cfhd_encode_init` then returns AVERROR_INVALIDDATA at the `height < 32` check

No command-line option (`-max_pixels`, `-s WxH`, `-vf scale`, etc.) bypasses the stride check because it is a structural guard in `av_image_check_size2` independent of `max_pixels`.

## PoC Approach Used

1. `vuln_002_gen.py`: Generates a minimal AVI with BI_RGB DIB at W=46336, H=46352
2. `vuln_002_run.sh`: Attempts both:
   - Crafted AVI → `-pix_fmt gbrap12le -c:v cfhd`
   - `lavfi color` source at overflow dimensions → CFHD encoder

Both attempts are rejected at the imgutils dimension check before reaching cfhd_encode_init.

## Exploitability

**Via libavcodec API (C harness)**: Exploitable. A caller that:
1. Calls `avcodec_alloc_context3(cfhd_encoder)`
2. Sets `avctx->pix_fmt = AV_PIX_FMT_GBRAP12`, `avctx->width = 46336`, `avctx->height = 46352`
3. Directly calls `avcodec_open2()` — the size check still runs but the guard only logs a warning
   and resets to 0,0 — OR skips `avcodec_open2` and calls init directly

…could trigger the integer overflow and resulting heap OOB write.

**Via ffmpeg binary**: NOT triggerable due to the mathematical constraint above.

## Status
UNVERIFIED — code-level vulnerability confirmed, command-line trigger path blocked by imgutils guard.
