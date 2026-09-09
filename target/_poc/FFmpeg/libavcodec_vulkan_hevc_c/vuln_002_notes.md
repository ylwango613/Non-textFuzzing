# VULN 002 – Skip Reason

## Vulnerability

Heap Buffer Overflow in `set_pps()` in `libavcodec/vulkan_hevc.c` (lines 532-533).

The loop:
```c
for (int i = 0; i < pps->num_tile_rows - 1; i++)
    vkpps->row_height_minus1[i] = pps->row_height[i] - 1;
```
writes to `row_height_minus1[]` without bounds-checking against the Vulkan SDK array limit of 21 elements. When `num_tile_rows >= 23`, writes occur at index 21+, overflowing the heap-allocated buffer.

## Why Skipped

**Vulkan hardware is not available on this system.**

Verification:
- `vulkaninfo` produced no output (command not found or no Vulkan ICD present).
- `ffmpeg -hwaccels` listed no hardware acceleration methods at all — the Vulkan hwaccel decoder is not compiled in or has no usable GPU backend.

The trigger path (`ffmpeg -hwaccel vulkan -i crafted.hevc -f null -`) requires:
1. A GPU supporting Vulkan Video Decode H.265 (VK_KHR_video_decode_h265).
2. A Vulkan ICD (e.g., Mesa radv, NVIDIA proprietary) installed and visible to the runtime.
3. FFmpeg built with Vulkan support (`--enable-vulkan`).

Without meeting all three conditions, FFmpeg will refuse `-hwaccel vulkan` before ever reaching `set_pps()`, so no file-based PoC can trigger the overflow on this host.

## To Reproduce on a Capable System

On a machine with Vulkan GPU support, craft an HEVC Annex B file with:
- SPS: CTB size log2=4 (16 px), resolution tall enough that `ctb_height >= 23` (e.g., 368 px height → 23 CTB rows).
- PPS: `tiles_enabled_flag=1`, `num_tile_rows_minus1=22` (23 rows), `uniform_spacing_flag=0`, explicit `row_height_minus1` values.

Run:
```bash
ffmpeg -hwaccel vulkan -i crafted.hevc -f null -
```

With ASAN enabled, this should produce a heap-buffer-overflow report in `set_pps()` at the out-of-bounds write to `vkpps->row_height_minus1`.
