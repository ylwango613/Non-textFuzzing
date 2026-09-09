# VULN-001: Integer Overflow in RLE Length Calculation — SGI Encoder

## Summary

- **File**: `libavcodec/sgienc.c`, function `encode_frame()`, lines 156–161
- **CWE**: CWE-190 (Integer Overflow) → CWE-122 (Heap-Based Buffer Overflow)
- **Status**: UNVERIFIED (pipeline mitigation blocks trigger via ffmpeg CLI)

---

## Vulnerable Code

```c
// sgienc.c, encode_frame(), lines 156–161
tablesize = depth * height * 4;          // int, but computed as uint32
length = SGI_HEADER_SIZE;               // = 512
if (!s->rle)
    length += depth * height * width;
else
    // RLE is on by default (options: { .i64 = 1 })
    length += tablesize * 2 + depth * height * (2 * width + 1);  // OVERFLOW

if ((ret = ff_alloc_packet(avctx, pkt, bytes_per_channel * length)) < 0)
    return ret;
// ...
bytestream2_init_writer(&taboff_pcb, pbc.buffer, tablesize);  // buf_size = tablesize (WRONG)
bytestream2_skip_p(&pbc, tablesize);
bytestream2_init_writer(&tablen_pcb, pbc.buffer, tablesize);  // buf_size = tablesize (WRONG)
bytestream2_skip_p(&pbc, tablesize);
```

### Type analysis

- `width`, `height`, `depth`: declared `unsigned int`
- `tablesize`, `length`: declared `int`
- `tablesize * 2 + depth * height * (2 * width + 1)`:
  - `depth * height * (2 * width + 1)` → `uint32_t` multiplication (wraps at 2^32)
  - `tablesize * 2` → `int`, converted to `uint32_t` for the addition
  - Sum is `uint32_t`, can wrap to a small positive value
  - Result stored back into `int length` via `length += ...`

---

## Overflow Mechanics (RGBA, width=8189, height=65535)

| Term | Value |
|---|---|
| depth | 4 (SGI_RGBA) |
| tablesize = depth \* height \* 4 | 1,048,560 |
| depth \* height \* (2\*width+1) | 4,293,591,060 |
| tablesize\*2 + depth\*height\*(2W+1) | 4,295,688,180 |
| Overflow? | YES (> 2^32 = 4,294,967,296) |
| Wrapped value | 720,884 |
| Allocated length | 512 + 720,884 = **721,396 bytes** |
| True needed (tables alone) | 512 + 2×1,048,560 = 2,097,632 bytes |
| OOB write amount | ~327,164 bytes |

### Consequence

`taboff_pcb` is initialized with `buf_size = tablesize = 1,048,560`, but the packet
buffer is only 721,396 bytes. Writing `depth × height = 262,140` RLE offset entries
(each 4 bytes = 1,048,560 bytes total) into a buffer with only 720,884 free bytes
causes a **heap buffer overflow of 327,164 bytes**.

---

## Pipeline Mitigation

`av_image_check_size2()` in `libavutil/imgutils.c` line 301 applies a stride-based guard
**before** any frame reaches the encoder:

```c
if (stride * (h + 128ULL) >= INT_MAX) {
    av_log(..., "Picture size %ux%u is invalid\n", w, h);
    return AVERROR(EINVAL);
}
```

where `stride = bpp*w + 128*8` (bpp = bytes per pixel for the pixel format, or 8 if unknown).

### Mathematical proof of impossibility

To trigger the overflow we need:
```
h × (depth × (2w+1) + 8×depth) > 2^32          ... (OVERFLOW_NEEDED)
```

The pipeline allows only:
```
(bpp×w + 1024) × (h + 128) < 2^31−1 = INT_MAX   ... (CHECK_PASSED)
```

For any supported pixel format, these are mutually exclusive. The minimum gap (closest the
trigger dims can get to passing the check) is:

| Format | bpp=depth | max_h (check) | min_h (overflow) | Gap |
|---|---|---|---|---|
| RGBA | 4 | 8,032 | 8,192 | **−160** |
| RGB24 | 3 | 10,738 | 10,923 | **−185** |
| GRAY8 | 1 | 32,136 | 32,767 | **−631** |

All gaps are negative → **impossible to satisfy both conditions simultaneously**.

The check is applied at:
- `avcodec_open2()` for both encoder and decoder
- `ff_set_dimensions()` in every decoder
- `av_image_alloc()` for frame buffer allocation
- Filter graph buffer allocation (lavfi, scale, format, etc.)

---

## Trigger Attempts

All 4 attempts failed at the pipeline level, before reaching the SGI encoder:

1. `ffmpeg -f lavfi -i color=size=8189x65535 -vf format=rgba -frames:v 1 out.sgi`
   → `Picture size 8189x65535 is invalid`

2. `ffmpeg -f rawvideo -pixel_format rgba -video_size 8189x65535 -i /dev/zero -frames:v 1 out.sgi`
   → `Picture size 8189x65535 is invalid`

3. `ffmpeg -max_pixels INT64_MAX -f rawvideo -pixel_format gray8 -video_size 65535x32769 -i /dev/zero -frames:v 1 out.sgi`
   → `Picture size 65535x32769 is invalid` (stride check is independent of max_pixels)

4. `ffmpeg -f lavfi -i color=size=65535x32136 -vf format=gray -frames:v 1 out.sgi`
   → `Picture size 65535x32136 is invalid` (lavfi uses rgba-format stride)

The SGI encoder does run correctly at small dimensions (confirmed at 100×100 gray8).

---

## Exploitability Assessment

### Via ffmpeg CLI (this build): NOT TRIGGERABLE
The hard-coded stride-based size guard in `av_image_check_size2` always blocks the necessary dimensions.

### Via libavcodec API (direct): THEORETICALLY TRIGGERABLE
A caller using libavcodec directly could manipulate `avctx->width` and `avctx->height` after
`avcodec_open2()` returns, bypassing the guard and directly triggering `encode_frame()` with
the overflow dimensions. This pattern might occur in:
- Applications with custom dimension-setting logic after codec initialization
- Older libavcodec versions before the stride-overflow check was added
- Embedded or stripped builds with the check disabled or absent

### Fix
The fix should use `size_t` or `int64_t` for the `length` computation, or add explicit
overflow checks before `ff_alloc_packet`:

```c
// Proposed fix: use int64_t for intermediate calculation
int64_t length64 = (int64_t)SGI_HEADER_SIZE + (int64_t)tablesize * 2 +
                   (int64_t)depth * height * (2 * width + 1);
if (length64 > INT_MAX) return AVERROR_INVALIDDATA;
length = (int)length64;
```

---

## Files

| File | Description |
|---|---|
| `vuln_001_gen.py` | Documents the overflow math, validates trigger/check constraints |
| `vuln_001_run.sh` | Runs 4 trigger attempts, captures ffmpeg output |
| `vuln_001_result.txt` | Full output from all attempts |
| `vuln_001_status.txt` | Status: UNVERIFIED with explanation |
| `vuln_001_notes.md` | This file |
