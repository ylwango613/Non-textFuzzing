# VULN 001 — Integer Overflow in s302m_encode2_frame() — SKIPPED

## Why Skipped

**The vulnerability cannot be triggered by passing a crafted media file to the ffmpeg command line.**

The root cause is a mutual exclusion between the overflow trigger condition and FFmpeg's internal frame allocation bounds check, with the two thresholds being exactly 1 apart.

---

## Trigger Condition Analysis

The integer overflow requires `nb_samples = 536870912` (for `nb_channels=2`, `bits_per_raw_sample=16`):

```
nb_samples * nb_channels * (bits_per_raw_sample + 4) / 8
= 536870912 * 2 * 20 / 8
= 21474836480 / 8           <- but computed in int32 FIRST
= (21474836480 mod 2^32) / 8 = 0 / 8 = 0
buf_size = 4 + 0 = 4
```

The guard check `buf_size - AES3_HEADER_LEN > UINT16_MAX` becomes `0 > 65535 = false` and is bypassed.

---

## Why the Frame Cannot Be Created (Upstream Blocker)

FFmpeg's `av_samples_get_buffer_size()` (libavutil/samples.c) guards every audio frame allocation with an overflow check:

```c
// For AV_SAMPLE_FMT_S16, nb_channels=2:
line_size = nb_samples * 2;          // bytes per channel
if (nb_channels > INT_MAX / line_size)
    return AVERROR(EINVAL);          // overflow guard
```

At `nb_samples = 536870912`:
- `line_size = 536870912 * 2 = 1073741824`
- `INT_MAX / 1073741824 = 1` (integer division)
- `nb_channels (2) > 1` → **EINVAL returned — frame allocation rejected**

At `nb_samples = 536870911` (one less, the maximum allocatable):
- `line_size = 536870911 * 2 = 1073741822`
- `INT_MAX / 1073741822 = 2` (integer division)
- `nb_channels (2) > 2` → **false — frame allocation succeeds**

But at 536870911 samples, the s302m encoder guard catches the (now-negative) overflow:
- `536870911 * 40 = -40` (int32 wrap)
- `buf_size = 4 + (-40)/8 = -1`
- `(uint32_t)(-1 - 4) = 4294967291 > 65535` → **guard fires, returns EINVAL**

---

## The Perfect Mutual Exclusion

| nb_samples   | av_samples_alloc result | s302m guard result |
|--------------|-------------------------|--------------------|
| 536870911    | OK (accepted)           | FIRES — caught     |
| **536870912**| **EINVAL — rejected**   | **bypassed (bug!)**|

These two values are exactly adjacent because:
- The int32 zero-wrap happens at `2^32 / gcd(40, 2^32) = 2^32 / 8 = 536870912` samples
- The max allocatable stereo s16 frame is `floor(INT_MAX / (2 * 2)) = floor((2^31 - 1) / 4) = 536870911` samples

No intermediate value exists that both (a) is allocatable by FFmpeg's pipeline and (b) bypasses the s302m guard.

---

## Evidence from Empirical Testing

We attempted to force 536870912 samples using FFmpeg's `asetnsamples` lavfi filter:

```bash
ffmpeg -f lavfi -i "anullsrc=cl=stereo:r=48000" \
  -af "asetnsamples=n=536870912:p=0" \
  -frames:a 1 -c:a s302m -strict experimental -f null -
```

Result: `[af#0:0] Error while filtering: Cannot allocate memory` — the filter graph failed when asetnsamples attempted to allocate the 2,147,483,648-byte output frame (which hits the same `av_samples_get_buffer_size` overflow check).

---

## Vulnerability Assessment

- **Code-level vulnerability**: REAL. The integer overflow exists and the guard check is genuinely bypassable.
- **Runtime reachability via ffmpeg CLI**: ZERO. No combination of input file, demuxer options, or audio filters can deliver a 536870912-sample frame to the encoder through the normal pipeline.
- **Potential exploitability**: Only through direct API usage (custom caller that manually crafts an AVFrame with falsified `nb_samples` and skips normal allocation), which is outside the attack surface of the `ffmpeg` binary.

---

## Encoder Capability Note

The s302m encoder declares `AV_CODEC_CAP_VARIABLE_FRAME_SIZE` (no fixed frame_size in init), so the skip reason is NOT a fixed frame_size. The skip is because FFmpeg's frame allocation infrastructure acts as an inadvertent upstream guard, making the exact overflow trigger value unreachable.
