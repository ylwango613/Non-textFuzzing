# ProSumer decode_init Integer Overflow – PoC Notes

## Vulnerability Summary

**File**: `libavcodec/prosumer.c`  
**Lines**: 339–345 (overflow), 167 (OOB write), 177 (OOB read)  
**FourCC**: `BT20` (confirmed in `libavformat/riff.c` line 489)

## Root Cause

In `decode_init()`:

```c
s->stride = 3LL * FFALIGN(avctx->width, 8) >> 1;   // computed in 64-bit
s->size   = avctx->height * s->stride;               // OVERFLOW: both operands uint32/int
```

`s->stride` and `s->size` are `unsigned` (32-bit). For `width=65536`:
- `stride = 3 * 65536 / 2 = 98304` (fits in uint32 — no truncation here)

For `height=43692`:
- `s->size = 43692 * 98304 = 4,295,098,368 → wraps mod 2^32 → 131,072`
- `av_malloc(131072)` allocates only 128 KB

In `decode_frame()` → `vertical_predict()`:

```c
vertical_predict((uint32_t*)s->decbuffer, s->stride, (uint32_t*)s->decbuffer,
                 s->stride, avctx->height - 1);
```

This iterates `43691` times with `stride = 98304` bytes/row, writing
`43691 × 98304 ≈ 4.3 GB` past a 128 KB buffer → **heap-buffer-overflow**.

## PoC Approach

1. **AVI container**: valid-enough RIFF/AVI structure with one video stream.
2. **FourCC `BT20`**: maps to `AV_CODEC_ID_PROSUMER` (via `ff_codec_bmp_tags`).
3. **BITMAPINFOHEADER**: `biWidth=65536`, `biHeight=43692`.
4. **Frame data**: 512 zero bytes (needed to reach `decode_frame()`).
5. **`-discard_damaged_percentage 100`**: bypasses the completeness check in
   `decode_frame()` that would otherwise reject a mostly-undecoded frame.

## Known Limitation

In this FFmpeg version, `avcodec_open2()` calls `ff_set_dimensions()` (in
`libavcodec/avcodec.c` lines 233–238) which internally calls
`av_image_check_size2()` (in `libavutil/imgutils.c` line 301):

```c
if (stride*(h + 128ULL) >= INT_MAX)  // stride = 8*w + 1024
    return AVERROR(EINVAL);
```

For any dimension pair that would cause the ProSumer overflow
(`h × 3w/2 > 2^32`), `av_image_check_size2` with `stride = 8w` already
fails (since `8w × h > 5.3 × 3w/2 × h > 5.3 × 2^32 >> 2^31`). This
means the dimensions are rejected and `decode_init()` is never called.

Additionally, `max_pixels` defaults to `INT_MAX` (from `options_table.h`
line 402), and `65536 × 43692 = 2,863,388,912 > INT_MAX`, which triggers
a second rejection path.

**Mathematical proof of non-exploitability via command line**:

| Quantity | Constraint |
|---|---|
| av_image_check_size2 requires: | `8w × h < 2^31 ≈ 2.15 × 10^9` |
| ProSumer overflow requires:    | `1.5w × h > 2^32 ≈ 4.29 × 10^9` |
| Ratio (ProSumer / av_check):   | `(1.5w × h) / (8w × h) = 3/16 ≈ 0.19` |

For both to hold simultaneously: `2^31 / 8 > 2^32 * 2/3` → `2^28 > 2^33/3` →
`268M > 2863M` → **FALSE**. No valid dimension pair exists.

## Files

- `vuln_001_gen.py` – generates `vuln_001_input.avi`
- `vuln_001_run.sh` – runs `ffmpeg` and captures output/ASAN logs
- `vuln_001_result.txt` – ffmpeg output
- `vuln_001_status.txt` – VERIFIED_CRASH / UNVERIFIED / ERROR

## Expected Result

FFmpeg will log `"Ignoring invalid width/height values"` (or similar) and
exit cleanly without crashing. The status is **UNVERIFIED** — the code
vulnerability exists but is gated by `av_image_check_size2` in this build.

The vulnerability would be reachable via direct FFmpeg API calls that bypass
`avcodec_open2`'s dimension validation, or in older FFmpeg versions that had
weaker dimension checks.
