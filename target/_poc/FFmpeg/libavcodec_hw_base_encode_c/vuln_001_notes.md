# VULN 001 – ts_ring OOB Write via Unbounded output_delay in HW Encoder

## Status: SKIPPED

## Reason

The vulnerability in `libavcodec/hw_base_encode.c` (lines 488-490, 555-556) can only be triggered through a hardware encoder such as VAAPI, D3D12VA, or Vulkan. The code path in `hw_base_encode.c` is not reachable by software encoders (e.g., libx264).

## Assessment Results

- **DRI devices present**: Yes (`/dev/dri/renderD128` through `renderD131` exist).
- **VAAPI encoders in ffmpeg binary**: None found (`ffmpeg -encoders | grep vaapi` returned no results).
- **Other HW encoders (nvenc, qsv, d3d12, vulkan, amf)**: None found.
- **Hardware acceleration methods**: Empty (`ffmpeg -hwaccels` returned no entries).

The ffmpeg binary at `/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg` was compiled without any hardware encoder support. While DRI render nodes are present on the host, the ffmpeg binary cannot utilize them for encoding because the required codec libraries (libva, libvulkan, etc.) were not linked during compilation.

## Trigger Conditions Not Met

The OOB write requires:
1. A hardware encoder that calls into `hw_base_encode.c` (h264_vaapi, hevc_vaapi, av1_vaapi, etc.)
2. `-bf 17` (max_b_frames=17, setting output_delay=17 which exceeds MAX_REORDER_DELAY=16)
3. `-async_depth 64` (to make modulus = 3×17+64 = 115 > 112 = array size)
4. Encoding more than 113 frames to reach the OOB index

None of these can be exercised because no hardware encoder is available in the binary.

## Reproduction Command (hypothetical, if HW were available)

```bash
ffmpeg -i input_200frames.y4m -c:v h264_vaapi -bf 17 -async_depth 64 -f null -
```

This would produce indices 112, 113, 114 into `ts_ring[112]`, writing out-of-bounds on frame 113+.
