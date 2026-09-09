# VULN 002 - Skip Notes

## Vulnerability Summary

- **Title**: Out-of-Bounds Write on ctx->slots[32] When maxDpbSlots Exceeds Array Size
- **Function**: `vulkan_encode_issue()`
- **Lines**: 216-220
- **CWE**: CWE-787
- **Status**: SKIPPED

## Why This Is Skipped

This vulnerability **cannot** be triggered by passing a crafted media file to the `ffmpeg` command line.

### Root Cause

`FFVulkanEncodeContext` contains a fixed-size array `FFHWBaseEncodePicture *slots[32]`. The loop at lines 216-219:

```c
for (int i = 0; i < ctx->caps.maxDpbSlots; i++) {
    ctx->slots[i] = ...;  // OOB write when i >= 32
}
```

`ctx->caps.maxDpbSlots` is populated by the Vulkan API call `vk->GetPhysicalDeviceVideoCapabilitiesKHR()`, which queries the **GPU driver** for hardware capabilities. If the GPU driver reports `maxDpbSlots > 32`, the loop will write past the end of the 32-element array, causing a heap out-of-bounds write.

### Why a Crafted File Cannot Trigger This

1. The trigger condition (`maxDpbSlots > 32`) comes from the GPU driver's capability report, not from any media file input.
2. FFmpeg reads `maxDpbSlots` directly from the Vulkan physical device capabilities structure filled by the driver — there is no code path by which file content influences this value.
3. A crafted media file (e.g., crafted MP4/H.264 bitstream) is parsed at the codec/demuxer layer, which is completely separate from the Vulkan device capability query that occurs during encoder initialization.
4. Exploitation would require either: (a) a real GPU driver that natively reports `maxDpbSlots > 32`, or (b) a patched/malicious GPU driver that reports an inflated value.

### Verification

Running `ffmpeg -encoders | grep -i vulkan` on the test build returns no output, confirming that no Vulkan video encoders are compiled into this build, making the code path entirely unreachable even with appropriate hardware.

### Attack Vector Assessment

- **Requires**: Compatible or buggy GPU driver reporting `maxDpbSlots > 32`
- **File-based trigger**: Not possible
- **Hardware requirement**: Vulkan-capable GPU with Vulkan Video encode extension support
- **Classification**: Driver/hardware-dependent vulnerability, not a file-parsing vulnerability
