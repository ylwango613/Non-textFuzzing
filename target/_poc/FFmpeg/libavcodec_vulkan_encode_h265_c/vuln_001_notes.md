# VULN 001 - SKIPPED

## Vulnerability Summary

**Title**: OOB Write in base_unit_to_vk() via Tile Column/Row Array Size Mismatch  
**File**: libavcodec/vulkan_encode_h265.c  
**Lines**: 1110-1114  
**CWE**: CWE-787 (Out-of-bounds Write)

## Why This Vulnerability Is SKIPPED

### 1. Encoder Path, Not Decoder/Parser Path

The vulnerability exists in `base_unit_to_vk()`, which is called from `create_session_params()` during H.265 Vulkan encoding. This is strictly an **encoder** code path, not triggered by parsing or decoding a crafted media file.

### 2. Requires Vulkan GPU Hardware and Drivers

The `hevc_vulkan` encoder codec requires:
- A physical GPU with Vulkan support
- Properly installed Vulkan drivers (e.g., NVIDIA proprietary, AMD AMDVLK/RADV, Intel ANV)
- Vulkan instance and device initialization to succeed

Without actual Vulkan hardware and drivers present, the `hevc_vulkan` encoder will fail to initialize entirely, and `base_unit_to_vk()` will never be reached.

### 3. Triggered by Encoder Configuration Parameters, Not Crafted Input Files

The vulnerability is triggered by passing 21 or more tile columns to the encoder (e.g., `-tiles 21x1`). This is an encoder configuration parameter, not something encoded inside a media container file that ffmpeg reads as input.

The trigger command would be:
```
ffmpeg -i <input> -c:v hevc_vulkan -tiles 21x1 output.mp4
```

This is fundamentally different from passing a crafted malformed input file — it is a **configuration flag** applied to the encoder.

### 4. Cannot Be Triggered by Crafted Malformed Media File

The allowed PoC method (crafting a malformed media container file and passing it to `ffmpeg`) cannot trigger this vulnerability because:
- The OOB write occurs during encoder initialization/configuration, not during input parsing
- No data from an input media file flows into `base_unit_to_vk()` or the tile column count
- Even if a crafted file could somehow reach the encoder path, Vulkan hardware absence would prevent encoder initialization

### 5. Rule Alignment

Per the defined SKIPPED condition: "漏洞无法通过向 ffmpeg 命令行传递一个畸形媒体文件来触发" (the vulnerability cannot be triggered by passing a crafted malformed media file to ffmpeg).

This vulnerability strictly requires:
1. Vulkan GPU hardware and drivers (environment prerequisite)
2. Encoder configuration flags (`-tiles 21x1`), not a crafted input file

Therefore, this vulnerability **cannot** be triggered by the allowed PoC method and is classified as **SKIPPED**.
