# VULN 001 - Skip Reason

**Vulnerability**: Integer overflow in bitstream_size accumulation leading to undersized D3D12 buffer and OOB write

**Affected code**: `libavcodec/d3d12va_vc1.c`, functions `d3d12va_vc1_decode_slice()` / `d3d12va_vc1_end_frame()` / `update_input_arguments()`, lines 89 / 165-167 / 113-137

## Why This Is Skipped

### 1. D3D12VA is a Windows-only API

The vulnerability resides in `d3d12va_vc1.c`, which implements hardware-accelerated VC1/WMV3 decoding via Direct3D 12 Video Acceleration (D3D12VA). D3D12 (Direct3D 12) is a Microsoft Windows-exclusive graphics API. This ffmpeg binary runs on Linux and cannot have D3D12VA support compiled in — the relevant code paths are gated behind `#ifdef` guards that require Windows headers (`d3d12.h`, `d3d12video.h`).

### 2. The trigger requires `-hwaccel d3d12va`

The attack vector requires invoking ffmpeg with `-hwaccel d3d12va`, which selects D3D12 hardware acceleration. On Linux this option is simply unavailable; ffmpeg would reject it immediately with an "Unknown hwaccel name" error even before any media file is parsed.

### 3. Practical infeasibility of the overflow condition

Even if a Windows + D3D12-capable environment were available, triggering the integer overflow in the `bitstream_size` accumulation requires more than 4 GB of total slice data within a single video frame. This would require approximately 1024 slices each carrying roughly 4 MB of slice payload — a degenerate input far outside the range of normal VC1/WMV3 content and impractical to construct as a simple PoC media file.

## Conclusion

This vulnerability cannot be triggered by passing a crafted media file to the ffmpeg binary on this Linux system. No `_gen.py` or `_run.sh` files are generated.
