# VULN-001: Progressive JPEG blocks[] Heap OOB Write

## Vulnerability Summary

**Type**: Heap-based Buffer Overflow (CWE-122)
**Functions**: `ff_mjpeg_decode_sos()` / `mjpeg_decode_scan()`
**Root Cause Lines**: 1754-1757 (OOB mb_width), 809-819 (under-allocation)
**Status**: UNVERIFIED — pixel format guard in `ff_mjpeg_decode_sof()` prevents the trigger

## Root Cause

In `ff_mjpeg_decode_sof()` (line 809-819), `blocks[i]` is allocated using:

```c
int bw = (width  + s->h_max * 8 - 1) / (s->h_max * 8);   // = 3 (width=72, h_max=3)
int bh = (height + s->v_max * 8 - 1) / (s->v_max * 8);   // = 1 (height=8)
int size = bw * bh * s->h_count[i] * s->v_count[i];       // = 6 for comp[1] (h_count=2)
s->block_stride[i] = bw * s->h_count[i];                  // = 6 for comp[1]
```

In `ff_mjpeg_decode_sos()` (lines 1753-1757), for a non-interleaved scan (`nb_components_sos=1`):

```c
h = s->h_max / s->h_scount[0];   // = 3/2 = 1 (INTEGER DIVISION rounds down!)
s->mb_width = (s->width + h * block_size - 1) / (h * block_size);  // = 79/8 = 9
```

The integer division `3/2=1` instead of `3.0/2=1.5` means `mb_width=9`, which exceeds the
6-entry allocation for `blocks[1]`.

## OOB Write Trigger (Theoretical)

In `mjpeg_decode_scan()` (line 1547), for progressive DC scan:

```c
int block_idx = s->block_stride[c] * (v * mb_y + y) + (h * mb_x + x);
// When mb_x=8: block_idx = 6*0 + 8 = 8   (out of bounds, size=6)
int16_t *block = s->blocks[c][block_idx];   // OOB write of 64 int16_t values
```

## Why the PoC is UNVERIFIED

The vulnerable configuration requires 3:2:1 chroma subsampling (pix_fmt_id=`0x31211100`):
- Component 0: h=3, v=1 (sets h_max=3)
- Component 1: h=2, v=1 (h_max % h_count = 3%2 = 1 ≠ 0 — the non-divisible component)
- Component 2: h=1, v=1

This format is **not recognized** by FFmpeg's pixel format switch in `ff_mjpeg_decode_sof()`
(lines 539-723). The switch only handles standard subsampling ratios where all h_counts are
powers-of-2 factors of each other. The format check at line 717-722 triggers:

```c
avpriv_report_missing_feature(s->avctx, "Pixel format 0x%x bits:%d", pix_fmt_id, s->bits);
return AVERROR_PATCHWELCOME;
```

This return happens **before** the `if (s->progressive)` block at line 808 that allocates
`blocks[]`. Since `ff_mjpeg_decode_sof()` fails, the frame decode loop does `goto fail`, and
the SOS marker is never processed.

**Mathematical proof that no recognized format can trigger OOB:**
For all recognized JPEG subsampling formats, all h_counts are powers of 2 (1, 2, 4) and h_max
is the maximum. Since h_max is also a power of 2, it is always divisible by every h_count.
Therefore h_sos = h_max / h_count[c] is always exact (no rounding), and the resulting mb_width
never exceeds the allocated block_stride.

Additionally, for any h_count k that is a divisor of h_max:
  mb_width = ceil(width/(h_max/k * 8)) ≤ k * ceil(width/(h_max*8)) = k * bw = block_stride[c]
This inequality holds with equality only in specific cases, preventing OOB.

## Alternative PoC (vuln_001_input_alt.jpg)

Uses recognized format 0x31111100 (3:1:1 — YUV444P with horizontal upscaling):
- All h_counts divide h_max: 3%3=0, 3%1=0
- SOF passes, blocks[] allocated, SOS processed successfully
- NO OOB occurs: mb_width=9 ≤ block_stride[0]=9 (exactly at the boundary)
- Exercises lines 1754-1757 and 1547-1549 of mjpegdec.c but without triggering the bug

This alternative runs successfully (frame decoded, exit code 0).

## PoC Files

- `vuln_001_input.jpg`: Primary trigger (3:2:1 subsampling) — REJECTED by pixel format check
- `vuln_001_input_alt.jpg`: Alternative (3:1:1 subsampling) — processes without OOB
- `vuln_001_gen.py`: Python script generating both files
- `vuln_001_run.sh`: Runner testing both files with ASAN-instrumented FFmpeg

## Conditions for Actual Exploitation

The vulnerability could be triggered if:
1. The pixel format guard is disabled (e.g., patched out or compiled without AVERROR_PATCHWELCOME)
2. A new recognized pixel format with non-power-of-2 h_count ratios is added to FFmpeg
3. An older version of FFmpeg without the pixel format check is used
4. A different decoder path that bypasses `ff_mjpeg_decode_sof()` is exercised

## Trigger Path (Theoretical)

```
ffmpeg -i crafted.jpg -f null -
  → ff_mjpeg_decode_frame_from_buf()
  → [SOF2] ff_mjpeg_decode_sof()   ← fails here with AVERROR_PATCHWELCOME
  → [SOS]  ff_mjpeg_decode_sos()   ← never reached
  → [DC scan] mjpeg_decode_scan()  ← never reached
    → block_idx=8 OOB on blocks[1][size=6]  ← never reached
```
