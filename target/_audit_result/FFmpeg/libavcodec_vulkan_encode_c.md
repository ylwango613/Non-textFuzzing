Based on my thorough multi-pass analysis of `vulkan_encode.c` (1173 lines) and related files `vulkan_encode.h`, `hw_base_encode.h`, `vulkan_encode_av1.c`, and `libavutil/vulkan.c`, here are the confirmed memory safety findings:

**Group 1 (lines 185-186)**: `max_pkt_size` declared as `int`, computed as `3 * surface_width * surface_height` — both `int` — with no overflow guard. Signed integer overflow (UB) wraps to a small positive value for specific extreme widths/heights, causing `ff_vk_get_pooled_buffer` to allocate a severely undersized GPU buffer.

**Group 2 (lines 216-219)**: `ctx->slots[32]` is fixed at 32 elements, but the loop iterates up to `ctx->caps.maxDpbSlots` (uint32_t from GPU driver) without any upper-bound check.

**Group 3 (lines 571-578)**: `query_data[0]` + `query_data[1]` (GPU encode feedback, uint32_t each) drive a `memcpy` length with no check against `sd_buf->size`.

**Group 4 (vulkan_encode_av1.c line 1091)**: `vulkan_encode_av1_write_obu` ignores its `data_len` input parameter and does `memcpy(data, obu->data, obu->data_size)` unconditionally; when invoked with `vp->tail_data` (char[16]), overflows the heap if `obu->data_size > 16`.

---

## VULN: Signed Integer Overflow in max_pkt_size Leading to Heap Underallocation
- **漏洞类别**: memory-safety
- **函数**: vulkan_encode_issue()
- **行号**: 160-194
- **CWE**: CWE-190 (Integer Overflow or Wraparound)
- **CVSS v3.1**: 7.8 (AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted media file (transcoding scenario)
- **外部触发路径**: ffmpeg -i crafted_large_res.mp4 -c:v hevc_vulkan output.mp4 -> avcodec_receive_packet() -> ff_hw_base_encode_receive_packet() -> vulkan_encode_issue() -> signed overflow in `3 * surface_width * surface_height` -> ff_vk_get_pooled_buffer() with underallocated size
- **描述**: Line 160 declares `int max_pkt_size`. Line 185 computes `max_pkt_size = FFALIGN(3 * ctx->base.surface_width * ctx->base.surface_height + (1 << 16), alignment)`, where `surface_width` and `surface_height` are both `int`. For frame dimensions where `3 * w * h` exceeds INT_MAX (2,147,483,647), C signed integer overflow (UB) occurs. For specific dimension values (e.g., w = h ≈ 37839), the true product wraps modulo 2^32 to a small positive int (~702467), causing FFALIGN to produce a ~768 KB `max_pkt_size` instead of the correct ~4.3 GB. This small value is passed as `size_t` to `ff_vk_get_pooled_buffer`, creating a severely underallocated Vulkan GPU output buffer. The GPU encoder writes encoded bitstream data into this small buffer and reports actual bytes written via query feedback. At lines 571-578, this feedback-derived `size` is used without bounds checking as the length for `memcpy(pkt->data + prev_size, sd_buf->mapped_mem, size)`, reading beyond the underallocated buffer.
- **触发条件**: Crafted input media file with frame dimensions causing `3 * w * h` to overflow `int` to a small positive value on a Vulkan-capable GPU supporting those dimensions. The threshold overflow starts at width × height > ~715,827,882 pixels.
- **安全影响**: Heap buffer over-read (information leak from adjacent heap memory into encoded output packet), potential heap corruption if GPU driver writes beyond the physical buffer boundary. In worst case, RCE via heap layout manipulation.

## VULN: Out-of-Bounds Write on ctx->slots[32] When maxDpbSlots Exceeds Array Size
- **漏洞类别**: memory-safety
- **函数**: vulkan_encode_issue()
- **行号**: 216-220
- **CWE**: CWE-787 (Out-of-bounds Write)
- **CVSS v3.1**: 7.0 (AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted media file / GPU driver capability
- **外部触发路径**: ffmpeg -i input.mp4 -c:v h264_vulkan output.mp4 -> ff_vulkan_encode_init() -> vk->GetPhysicalDeviceVideoCapabilitiesKHR() returns maxDpbSlots > 32 -> vulkan_encode_issue() -> loop iterates ctx->slots[i] for i >= 32 -> heap OOB write
- **描述**: In `vulkan_encode.h` line 198, `FFVulkanEncodeContext` contains `FFHWBaseEncodePicture *slots[32]` — a fixed 32-element array. In `vulkan_encode_issue()` at lines 216-219, the loop iterates `for (int i = 0; i < ctx->caps.maxDpbSlots; i++)` where `ctx->caps.maxDpbSlots` is a `uint32_t` value returned by `vk->GetPhysicalDeviceVideoCapabilitiesKHR()` with no upper bound validation anywhere in FFmpeg. If the GPU driver reports `maxDpbSlots > 32`, the loop writes `base_pic` to `ctx->slots[i]` for `i >= 32`, past the array boundary into adjacent struct fields (`prev_buf_ref` and `prev_buf_size` at lines 200-201 of the header). The same OOB read occurs at line 44 in `vulkan_encode_free_pic`: `ctx->slots[vp->dpb_slot.slotIndex] = NULL` when `slotIndex >= 32`.
- **触发条件**: Vulkan device driver reporting `maxDpbSlots > 32` combined with any encoding session that reaches more than 32 concurrent DPB slots. No explicit crafted input file required — only requires a compatible (or buggy) GPU driver.
- **安全影响**: Heap corruption of `FFVulkanEncodeContext.prev_buf_ref` and `prev_buf_size`, leading to use-after-free or type confusion on subsequent encode output operations. In the worst case, RCE via heap layout manipulation.

## VULN: Unchecked GPU Query Feedback Used Directly as memcpy Length
- **漏洞类别**: memory-safety
- **函数**: vulkan_encode_output()
- **行号**: 568-579
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 5.6 (AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:L)
- **严重程度**: Medium
- **攻击向量**: crafted media file (transcoding)
- **外部触发路径**: ffmpeg -i crafted.mp4 -c:v hevc_vulkan output.mp4 -> vulkan_encode_output() -> ff_vk_exec_get_query() returns GPU feedback -> size = slices_offset + query_data[0] + query_data[1] > sd_buf->size -> memcpy(pkt->data + prev_size, sd_buf->mapped_mem, size) OOB read
- **描述**: At line 571, `size_t size = (vp->slices_offset + query_data[0] + query_data[1])` where `query_data[0]` (bitstream buffer secondary offset, uint32_t) and `query_data[1]` (bytes written, uint32_t) come directly from GPU encode feedback queried via `ff_vk_exec_get_query`. There is no validation that `size <= sd_buf->size` (the actual GPU buffer allocation size). At line 578, `memcpy(pkt->data + prev_size, sd_buf->mapped_mem, size)` then copies `size` bytes from `sd_buf->mapped_mem`. If the GPU driver (due to a bug, device error, or underallocated buffer from the preceding `max_pkt_size` overflow) reports `query_data[0] + query_data[1] > sd_buf->size - vp->slices_offset`, this reads beyond the allocated GPU-mapped heap buffer, exposing adjacent heap contents into the output encoded packet. The same pattern recurs at line 551 for `prev_buf_size`.
- **触发条件**: GPU driver reporting encode feedback values that sum to more bytes than the physical output buffer holds — achievable when (a) a driver bug exists, or (b) the `max_pkt_size` integer overflow (Finding 1) creates an underallocated buffer causing the GPU to signal errors or overcount.
- **安全影响**: Heap over-read leaking up to ~2 GB of adjacent heap memory into the encoded output bitstream, resulting in information disclosure (heap layout, pointers, sensitive codec state). In combination with Finding 1, this becomes a write primitive if an attacker can arrange a specific heap layout.

<!-- AUDIT_PROMPT_VERSION: 1 -->
