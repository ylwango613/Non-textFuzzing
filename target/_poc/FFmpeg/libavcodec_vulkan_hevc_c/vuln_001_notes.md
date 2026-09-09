# VULN 001 — SKIPPED

## Vulnerability

Heap Buffer Overflow in `set_pps()` in `libavcodec/vulkan_hevc.c` (lines 529–533).

The loop `for (int i = 0; i < pps->num_tile_columns - 1; i++)` writes to
`column_width_minus1[i]` without checking against the Vulkan SDK array bound
of 19 elements. When `num_tile_columns >= 21`, writes proceed out of bounds.

## Skip Reason

**Vulkan hardware support is not available on this system.**

Verification performed:
- `vulkaninfo 2>/dev/null | head -5` — produced no output (command not found or no devices)
- `ffmpeg -hwaccels 2>&1 | grep vulkan` — produced no output (vulkan not listed)

## Why This Cannot Be Triggered Without Vulkan

The vulnerable code path is only reached when:

1. FFmpeg is invoked with `-hwaccel vulkan`, and
2. An actual GPU with Vulkan Video Decode H.265 capability is present and
   enumerated by the Vulkan runtime.

Without a compatible GPU and the Vulkan runtime, FFmpeg will fall back to
software decoding and never enter `vk_hevc_create_params()` or `set_pps()`.
The heap overflow in `set_pps()` is therefore unreachable on this machine
regardless of how the input HEVC file is crafted.

## What Would Be Needed

- A system with a Vulkan-capable GPU (NVIDIA RTX/GTX 16xx+, AMD RX 5000+,
  Intel Arc, or similar) that supports the `VK_KHR_video_decode_h265` extension.
- The Vulkan runtime and validation layers installed (`libvulkan.so`,
  `vulkaninfo` returning device info).
- FFmpeg built with `--enable-vulkan` and linked against the Vulkan loader.
- Then: a crafted HEVC file with `num_tile_columns_minus1 >= 20` (21 columns)
  and an appropriately small CTB size (log2_ctb_size = 4 → 16 px CTBs) would
  trigger the out-of-bounds write inside `set_pps()`.
