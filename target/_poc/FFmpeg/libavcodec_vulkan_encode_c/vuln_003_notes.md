# VULN 003 - Skip Reason

## Vulnerability
- **Title**: Unchecked GPU Query Feedback Used Directly as memcpy Length
- **Function**: vulkan_encode_output()
- **CWE**: CWE-125 (Out-of-bounds Read)

## Why This Is Skipped

This vulnerability cannot be triggered by passing a crafted media file alone. The trigger path requires:

1. **Vulkan GPU hardware with Vulkan encode support**: The build-under-test was compiled without Vulkan support. Running `/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg -hwaccels` shows an empty list of hardware acceleration methods — Vulkan is not present.

2. **No Vulkan encoders available**: Running `/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg -encoders | grep -i vulkan` returned no output, confirming `hevc_vulkan` and related Vulkan encoders are not compiled in.

3. **GPU driver control required**: Even if Vulkan hardware were present, the vulnerability at line 571 of `libavcodec/vulkan_encode.c` depends on `query_data[0]` and `query_data[1]` returned by `ff_vk_exec_get_query()`. These values come from GPU encode feedback — they are not derived from the input media file's content. A crafted input file has no path to influence what the GPU driver reports back as query feedback values.

4. **Requires driver bug or integer overflow precondition**: The bug fires when the GPU signals a size exceeding `sd_buf->size`. This occurs either due to a GPU driver defect (not controllable via file input) or via the `max_pkt_size` integer overflow that causes an underallocated buffer — itself a separate code path that still requires a live Vulkan device to exercise.

## Conclusion

Triggering VULN 003 requires actual Vulkan GPU hardware, a Vulkan-enabled FFmpeg build, and specific GPU driver behavior (reporting inflated query feedback values). None of these conditions can be fulfilled by crafting an input media file on this system. The PoC is skipped.
