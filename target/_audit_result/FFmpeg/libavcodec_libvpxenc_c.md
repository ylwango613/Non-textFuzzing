Analysis complete. The full code review is done across all 2239 lines. Here is what I found:

**Group 1 (lines 1–1400):** Setup, codec control, two-pass stats, frame queue, packet storage — no externally-triggerable memory safety issues. The `storeframe` integer (`sz + 8`) and the `twopass_stats` `(sz + pkt_sz)` additions are both `size_t` on 64-bit and practically cannot overflow.

**Group 2 (lines 1400–1740):** ROI map handling (`set_roi_map`). The `rows * cols` product is bounded by VP9's max-dimension constraints so does not overflow `unsigned int`. The `self_size * i` pointer arithmetic uses `uint32_t * int` (promoted to `uint32_t`), but since `i < sd->size / self_size` the product can never exceed `sd->size`, which is a valid buffer. No exploitable bug here.

**Group 3 (lines 1737–1774): `realloc_alpha_uv` — confirmed integer overflow → heap overflow.**

- `stride[VPX_PLANE_U]` is `int` (declared as `int *stride = rawimg_alpha->stride`).
- `height` is `int` (function parameter from `frame->height`).
- Line 1755: `av_malloc_array(stride[VPX_PLANE_U], height)` uses `size_t` arithmetic and correctly allocates `stride × height` bytes if the system has memory.
- Lines 1764–1765: `av_memcpy_backptr(planes[VPX_PLANE_U] + 2, 2, stride[VPX_PLANE_U] * height - 2)` — the multiplication is **signed 32-bit**, not `size_t`. For `stride ≈ height ≈ 46342` (e.g., 46342 × 46342 = 2,147,582,164 > INT_MAX), the product wraps to a large negative integer (e.g., −2,147,385,132). Subtracting 2 gives −2,147,385,134. This negative `int` is passed as `cnt` to `av_memcpy_backptr`, which dispatches to `fill16(dst, −2,147,385,134)`. In `fill16`, `while (len >= 4)` is skipped (negative), but `while (len--)` runs approximately `2^32 − 2,147,385,134 ≈ 2.1 billion` iterations, writing the 2-byte UV fill pattern continuously far beyond the allocated buffer — a heap-based buffer overflow.
- Line 1767–1768: same overflow but the negative `int` is implicitly converted to a huge `size_t` passed to `memset`, effectively writing `SIZE_MAX` bytes (immediate crash, not controllable for RCE in the 8-bit path).

**Group 4 (lines 1775–2239):** Encoding loop and options — no memory safety issues.

## VULN: Integer Overflow in realloc_alpha_uv Leading to Heap Buffer Overflow via fill16
- **漏洞类别**: memory-safety
- **函数**: realloc_alpha_uv()
- **行号**: 1764-1765
- **CWE**: CWE-190 (Integer Overflow or Wraparound)
- **CVSS v3.1**: 7.5 (AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted media file
- **外部触发路径**: ffmpeg -i crafted_yuva_video.webm -c:v libvpx-vp9 out.webm -> vpx_encode() [libvpxenc.c:1810] -> realloc_alpha_uv(avctx, frame->width, frame->height) [libvpxenc.c:1737] -> av_memcpy_backptr(planes[VPX_PLANE_U]+2, 2, stride[VPX_PLANE_U]*height-2) [line 1764] -> fill16() [libavutil/mem.c:359] — while(len--) infinite-like write loop
- **描述**: 在 `realloc_alpha_uv()` 中，`stride[VPX_PLANE_U]`（类型 `int`，来自 `int *stride = rawimg_alpha->stride`）与 `height`（类型 `int`，来自 `frame->height`）相乘时使用有符号 32-bit 整数运算（`stride[VPX_PLANE_U] * height`）。当帧宽高均约 ≥ 46342 像素时（如 46342×46342），乘积 2,147,582,164 超过 INT_MAX（2,147,483,647），回绕为约 −2,147,385,132 的负值。此负值减 2 后作为 `int cnt` 传入 `av_memcpy_backptr(dst, 2, cnt)`，进而调用 `fill16(dst, cnt)`。在 `fill16` 中，`while(len >= 4)` 不执行（负数），但 `while(len--)` 从负数开始经过 2^32 次回绕才归零，向 `planes[VPX_PLANE_U]+2` 之后连续写入约 21 亿字节的堆数据，远超 `av_malloc_array` 分配的缓冲区边界，造成大范围堆溢出。注意 `av_malloc_array` 在第 1755 行使用 `size_t` 运算正确分配内存，不会返回 NULL，因此第 1757 行的检查不能拦截后续的整数溢出。
- **触发条件**: 攻击者提供一个包含 YUVA（带 Alpha 通道）10/12-bit 像素格式、帧尺寸≥46342×46342 像素的视频文件（VP9、AV1 等高分辨率编码格式理论上支持此尺寸），并将其转码为 libvpx VP9（如 `-c:v libvpx-vp9 -pix_fmt yuva420p10`）。需要目标系统有约 2GB 以上可用内存使 `av_malloc_array` 成功分配。
- **安全影响**: 在堆上写入约 2GB 的可预测字节模式（UV 填充值），可覆盖堆元数据和其他堆对象，最坏情况下通过堆溢出实现远程代码执行（RCE）；如无法利用则至少造成进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
