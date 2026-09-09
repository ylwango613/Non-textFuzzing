# PoC Notes: VULN 001 — Integer Overflow in VC2 Encoder DWT Buffer Allocation

## Vulnerability Location

- **File**: `libavcodec/vc2enc_dwt.c`
- **Function**: `ff_vc2enc_init_transforms()`
- **Line**: 266
- **Code**:
  ```c
  s->buffer = av_calloc((p_stride + slice_w)*(p_height + slice_h), sizeof(dwtcoef));
  ```

## Theoretical Overflow Path

Called from `vc2_encode_init()` in `vc2enc.c` at lines 1164-1167:
```c
if (ff_vc2enc_init_transforms(&s->transform_args[i].t,
                              s->plane[i].coef_stride,   // p_stride
                              s->plane[i].dwt_height,    // p_height
                              s->slice_width,            // slice_w
                              s->slice_height))          // slice_h
```

Where:
- `p->coef_stride = FFALIGN(FFALIGN(avctx->width, 2^wavelet_depth), 32)`
- `p->dwt_height  = FFALIGN(avctx->height, 2^wavelet_depth)`

For `avctx->width = avctx->height = 46000` with `wavelet_depth=4` (default):
- `coef_stride = FFALIGN(46000, 32) = 46016`
- `dwt_height = 46000`
- `slice_width = slice_height = 1024` (max option)
- Product: `(46016+1024) * (46000+1024) = 47040 * 47024 = 2212008960 > INT_MAX (2147483647)`
- 32-bit overflow → wraps to `2212008960 - 2^32 = -2082958336` → cast to `size_t` yields a tiny allocation
- Subsequent DWT writes 4×width×height elements → heap-buffer-overflow

## Why the Trigger Fails via Standard CLI

`avcodec_open2()` calls `ff_set_dimensions()` (`libavcodec/utils.c:91`):
```c
int ret = av_image_check_size2(width, height, s->max_pixels, AV_PIX_FMT_NONE, 0, s);
```

Inside `av_image_check_size2()` (`libavutil/imgutils.c:301`):
```c
int64_t stride = av_image_get_linesize(pix_fmt, w, 0);
if (stride <= 0)
    stride = 8LL*w;        // for AV_PIX_FMT_NONE: stride = 8*w
stride += 128*8;           // stride += 1024
if (stride*(h + 128ULL) >= INT_MAX) {
    return AVERROR(EINVAL);
}
```

For `w=46000`: `stride = 8*46000 + 1024 = 369024`. Then `369024 * (46000+128) = 17022339072 >> INT_MAX`. The guard fires.

In `avcodec.c:237`: `if (ret < 0) goto free_and_end;` — the encoder init callback is never called.

### Mathematical Proof of Incompatibility

For any `w, h > 0`, the two conditions are mutually exclusive:

1. **Guard passes**: `(8w + 1024)(h + 128) < 2147483647`
2. **Overflow fires**: `(w + 1024)(h + 1024) > 2147483647`

From (1): `h < INT_MAX / (8w+1024) - 128 ≈ INT_MAX / (8w)`
From (2): `h > INT_MAX / (w+1024) - 1024 ≈ INT_MAX / w`

For both to hold: `INT_MAX/w < h < INT_MAX/(8w)`, requiring `1/w < 1/(8w)`, i.e., `8w < w` — impossible.

Full search over all integer (w, h) confirmed no solution exists (see output of vuln_001_gen.py).

## PoC Approach

### Approach A — MKV at overflow-triggering dimensions (46000×46000)

Constructs a minimal Matroska container with:
- EBML Header + Segment + SegInfo + Tracks + Cluster
- Track: V_UNCOMPRESSED codec, ColorSpace=YV12 (→ yuv420p rawvideo), PixelWidth=46000, PixelHeight=46000
- One SimpleBlock with a 16-byte dummy payload

**Result**: The MKV file is parsed correctly (YV12 ColorSpace recognized as yuv420p, stream mapping to vc2 encoder is planned). However, `av_image_check_size2` rejects 46000×46000 during decoder `avcodec_open2()`, resetting dimensions to 0. The vc2 encoder is never opened ("Could not open encoder before EOF"). No ASAN output.

Key log lines:
```
[IMGUTILS] Picture size 46000x46000 is invalid
[rawvideo @ ...] width is not set
[vost#0:0/vc2 @ ...] Could not open encoder before EOF
```

### Approach B — lavfi nullsrc at maximum valid dimensions (16200×16200)

Exercises the vc2 encoder code path at the largest dimensions that pass all guards.
- `(8*16200+1024)*(16200+128) = 130624*16328 = 2133019072 < INT_MAX` — passes
- vc2enc at 16200×16200: `(FFALIGN(16200,32)+1024)*(FFALIGN(16200,16)+1024) = 17248*17256 = 297,693,488 << INT_MAX` — no overflow

**Result**: Encoder initializes, encodes one frame, completes normally. No ASAN output.

## Assessment

The vulnerability is **real at the source-code level** (the arithmetic at line 266 has no overflow guard and will misbehave if called with large `p_stride`/`p_height`). However, it is **not reachable via the standard ffmpeg CLI** because `ff_set_dimensions()` unconditionally uses `pix_fmt=NONE` (stride=8w) in its dimension check, which is ~8x more restrictive than the overflow threshold.

**Potential alternative triggers (not attempted, require C code or modified API usage)**:
- Direct library call to `avcodec_alloc_context3(vc2_encoder)` with manually set `ctx->width=46000, ctx->height=46000`, bypassing `ff_set_dimensions()`
- Fuzzing via `avcodec_open2` with the context dimensions pre-set through a different code path that skips the standard `avcodec_open2` checks
- Modified version of ffmpeg with the `av_image_check_size2` guard temporarily disabled

## Files

- `vuln_001_gen.py` — MKV generator with dimension analysis
- `vuln_001_run.sh` — Two-approach PoC runner
- `vuln_001_input.mkv` — Generated MKV with V_UNCOMPRESSED YV12 at 46000×46000
- `vuln_001_result.txt` — Full binary output
- `vuln_001_status.txt` — Final status: UNVERIFIED
