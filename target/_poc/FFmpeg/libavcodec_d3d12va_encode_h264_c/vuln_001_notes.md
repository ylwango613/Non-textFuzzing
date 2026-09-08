# VULN 001 - Skipped

## Vulnerability
- **File**: `libavcodec/d3d12va_encode_h264.c`
- **Function**: `d3d12va_encode_h264_init_picture_params()`
- **Lines**: 485-525
- **Type**: Heap OOB Write via undersized `pd` array

## Why Skipped

This vulnerability cannot be triggered by passing a malformed media file to the ffmpeg command line on this system.

The `h264_d3d12va` encoder relies on D3D12VA (Direct3D 12 Video Acceleration), which is a Windows-only API. The vulnerable code path is only reachable on Windows systems with D3D12-capable GPU hardware.

The current environment is Linux, and the ffmpeg binary at `/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg` is a Linux build. Confirmed: running `ffmpeg -encoders | grep d3d12` returns no output, meaning the `h264_d3d12va` encoder is not compiled in or available.

Therefore, the attack vector (`ffmpeg -i <input> -c:v h264_d3d12va -bf 2 <output>`) cannot be exercised on this platform, and no PoC can be generated or tested.
