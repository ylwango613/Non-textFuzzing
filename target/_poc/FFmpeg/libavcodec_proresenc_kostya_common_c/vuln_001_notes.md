# PoC Notes: Integer Overflow in frame_size_upper_bound (ProRes Encoder)

## Vulnerability

- **Function**: `ff_prores_kostya_encode_init()` in `libavcodec/proresenc_kostya_common.c`
- **Line**: 287 (the computation of `ctx->frame_size_upper_bound`)
- **Type**: Signed 32-bit integer overflow (C undefined behavior, detected by UBSan)

## Root Cause

`ff_prores_kostya_encode_init()` computes a buffer bound using signed int32 arithmetic:

```c
ctx->frame_size_upper_bound = (ctx->pictures_per_frame *
                               ctx->slices_per_picture + 1) *
                              (2 + 2 * ctx->num_planes +
                               (mps * ctx->bits_per_mb) / 8)
                              + 200;
```

For ProRes 4444 with an alpha channel (`ctx->alpha_bits = 16`), `bits_per_mb` is
multiplied by 20 (line ~252):

```c
if (ctx->alpha_bits)
    ctx->bits_per_mb *= 20;
```

With ProRes 4444 profile, `br_tab[3] = 1425` (the largest MB limit bucket), so
`bits_per_mb = 1425 * 20 = 28500`.

At dimensions 16224x16224 (1014 macroblocks per row/column):
- `slices_per_picture = 1014 * 128 = 129,792`
- `per_slice_base = 2 + 2*4 + 28500*16/8 = 28510`
- Step 1 multiplication: `(129793) * 28510 = 3,700,398,630` — overflows signed int32
  (max ~2.147 billion), wrapping to **-594,568,666**
- After adding the alpha term (598,086,144), the final value is **3,517,478 bytes**
  instead of the correct ~3.7 GB, an error of ~1000x

The encoder then calls `ff_alloc_packet(avctx, pkt, 3517478 + FF_INPUT_BUFFER_MIN_SIZE)`
and attempts to encode a 16224x16224 RGBA frame into the tiny buffer.

## Observed Behavior

UBSan reports the overflow at exactly the predicted site:

```
src/libavcodec/proresenc_kostya_common.c:287:65: runtime error:
  signed integer overflow: 129793 * 28510 cannot be represented in type 'int'
    #0 0x... in ff_prores_kostya_encode_init (ffmpeg+...)
    #1 0x... in encode_init (ffmpeg+...)
    #2 0x... in avcodec_open2 (ffmpeg+...)
```

The encoder proceeds with the corrupted bound and the prores_ks encoder itself later
reports the consequence during actual encoding:

```
[prores_ks @ ...] Packet too small: is 3517478, needs 376512 (slice: 30).
```

The allocated packet buffer (3,517,478 bytes) is far too small relative to the
correct requirement. In this build the "Packet too small" path is hit at slice 30,
halting encoding rather than writing past the buffer end. On builds without that
defensive check, encoding would continue writing into out-of-bounds memory, leading
to a heap-buffer-overflow write.

## Trigger Path

1. Input: QuickTime MOV container embedding a single-frame 16224x16224 RGBA PNG
   (color type 6, 8 bits/channel). RGBA format ensures FFmpeg decodes to
   `AV_PIX_FMT_RGBA` with an alpha plane, which forces the encoder into the
   alpha path (`alpha_bits = 16`, `bits_per_mb *= 20`).

2. Command:
   ```
   ffmpeg -i vuln_001_input.mov -c:v prores_ks -profile:v 4444 -f null -
   ```

3. The overflow occurs during encoder initialization (`avcodec_open2`), before any
   frame data is processed, so a valid but specially sized input file is sufficient.

## Overflow Arithmetic (int32)

| Variable                 | Value             |
|--------------------------|-------------------|
| slices_per_picture       | 129,792           |
| bits_per_mb (4444+alpha) | 28,500            |
| per_slice_base           | 28,510            |
| True product (int64)     | 3,700,398,630     |
| Overflowed int32         | -594,568,666      |
| alpha term               | +598,086,144      |
| frame_size_upper_bound   | 3,517,478 (wrong) |
| Correct value (approx.)  | ~3.7 GB           |

## Files

| File                    | Description                                   |
|-------------------------|-----------------------------------------------|
| `vuln_001_gen.py`       | Generates the 16224x16224 RGBA PNG + MOV      |
| `vuln_001_run.sh`       | Runs FFmpeg with ASAN/UBSAN env vars          |
| `vuln_001_input.mov`    | Crafted input (1,053,192 bytes)               |
| `vuln_001_result.txt`   | Full FFmpeg output including UBSan report     |

## Status

VERIFIED_BEHAVIOR — UBSan confirmed signed integer overflow at `proresenc_kostya_common.c:287`.
The overflow produces an undersized `frame_size_upper_bound`, which is then used as the
packet allocation size, leading to a buffer that is ~1000x too small for encoding the frame.
