# VULN 001 PoC Notes

## Vulnerability

**File**: libavcodec/vc2enc.c  
**Title**: vc2enc AVOption off-by-one allows OOB read and invalid function-pointer call via wavelet_idx=7

## Root Cause

The vc2 encoder's AVOption for `wavelet_type` permits index 7, but two arrays are only valid for indices 0-6:
- `ff_dirac_default_qmat[7][4][4]` — 7 rows (valid indices 0-6)
- `vc2_subband_dwt[7]` — 7 elements (valid indices 0-6)

When `wavelet_type=7` is passed, both arrays are accessed at index 7 (out-of-bounds), leading to an OOB read and a potentially invalid function-pointer call.

## PoC Approach

1. `vuln_001_gen.py`: Generates a minimal 16x16 YUV420p raw video frame (384 bytes). This is the smallest valid frame the vc2 encoder will accept.

2. `vuln_001_run.sh`: Invokes the FFmpeg binary with `-c:v vc2 -wavelet_type 7`, feeding the raw YUV frame. ASAN is configured to log errors without aborting so the full output is captured.

## Trigger Command

```bash
ffmpeg -f rawvideo -pixel_format yuv420p -video_size 16x16 -framerate 25 \
  -i vuln_001_input.yuv \
  -c:v vc2 -wavelet_type 7 \
  -f null -
```

## Expected Behavior

With ASAN enabled, expect a `heap-buffer-overflow` or similar memory error when the encoder accesses `ff_dirac_default_qmat[7]` or calls `vc2_subband_dwt[7]`.
