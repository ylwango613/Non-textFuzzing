After thoroughly reading all 372 lines of `vulkan_vp9.c` and tracing relevant structures (`vulkan_decode.h`, `vp9shared.h`, `cbs_vp9.h`, `cbs_vp9_syntax_template.c`), here is my complete analysis:

**Group 1 — `remap_interp()` (lines 91-103):** `raw_interpolation_filter_type` is parsed with `f(2, ...)` (2-bit CBS field → values 0–3); `remap[]` has exactly 4 entries. **Safe.**

**Group 2 — `ref_frame_idx` array bounds (lines 145-170, 275-283):** `ref_frame_idx[i]` is a 3-bit CBS field (0–7), `s->ref_frames` has 8 entries. **Safe.**

**Group 3 — `ref_count` overflow of `rvp`/`rav` in `vk_vp9_end_frame` (lines 330-344):** `referenceSlotCount` is set from `ref_count` which increments at most `STD_VIDEO_VP9_REFS_PER_FRAME` times per the outer loop. `rvp`/`rav` arrays are also sized `STD_VIDEO_VP9_REFS_PER_FRAME`. **Safe.**

**Group 4 — Missing NULL check for `hwaccel_picture_private` before dereference (lines 148/155 and 278/283):** The code assigns `hp = ref_frame->hwaccel_picture_private` then checks only `ref_frame->tf.f` for NULL. If `tf.f` is non-NULL but `hwaccel_picture_private` is NULL (e.g., a frame decoded without Vulkan hwaccel is left in `ref_frames[]`), dereferencing `hp->frame_id` crashes. **Confirmed memory safety defect.**

## VULN: NULL Dereference of hwaccel_picture_private Before tf.f-Only Guard in vk_vp9_start_frame
- **漏洞类别**: memory-safety
- **函数**: vk_vp9_start_frame()
- **行号**: 148-155
- **CWE**: CWE-476 (NULL Pointer Dereference)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted VP9 media file decoded via Vulkan HW acceleration
- **外部触发路径**: ffmpeg -hwaccel vulkan -i <crafted_vp9_file> -f null - -> avcodec_send_packet() -> vp9_decode_frame() -> vk_vp9_start_frame() -> hp->frame_id dereference at line 155
- **描述**: At line 148, `hp` is assigned from `ref_frame->hwaccel_picture_private` (may be NULL). At line 151 only `ref_frame->tf.f` is guarded for NULL and the loop continues past that point. At line 155, `hp->frame_id` is dereferenced without any NULL check on `hp`. If a VP9 reference frame in `s->ref_frames[idx]` has its `tf.f` set (AVFrame allocated) but `hwaccel_picture_private` not yet populated — for example, because an earlier Vulkan frame allocation partially failed, or because the frame was decoded via a different (software) path and left in the reference slot — `hp` is NULL and the dereference crashes the process. The same bug occurs a second time at lines 278/283 in the same function body, where the guard is `if (!ref_frame->tf.f) ... else hp->frame_id` without a NULL check on `hp`.
- **触发条件**: 攻击者提供一个含有 inter-frame 参考的 VP9 文件（非关键帧），并使 FFmpeg 通过 `-hwaccel vulkan` 解码。若某参考帧的 `tf.f`（AVFrame）已分配但 `hwaccel_picture_private`（Vulkan 私有数据）为 NULL（如之前帧分配失败或上下文切换），则必然触发 NULL 解引用。
- **安全影响**: 进程崩溃（DoS）。在极少数可将 NULL 地址映射的旧内核或特定平台配置下，理论上可进一步利用；现代 Linux 平台（`mmap_min_addr > 0`）限于 DoS。

## VULN: NULL Dereference of hwaccel_picture_private in Second Loop of vk_vp9_start_frame
- **漏洞类别**: memory-safety
- **函数**: vk_vp9_start_frame()
- **行号**: 278-283
- **CWE**: CWE-476 (NULL Pointer Dereference)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted VP9 media file decoded via Vulkan HW acceleration
- **外部触发路径**: ffmpeg -hwaccel vulkan -i <crafted_vp9_file> -f null - -> avcodec_send_packet() -> vp9_decode_frame() -> vk_vp9_start_frame() -> hp->frame_id dereference at line 283
- **描述**: In the second reference-slot loop (lines 275–283), `hp = ref_frame->hwaccel_picture_private` is stored at line 278. The NULL guard at line 280 checks only `ref_frame->tf.f`: if false, the else-branch at line 283 executes `hp->frame_id` unconditionally. If `hp` is NULL (same conditions as the first finding: Vulkan private data missing while the AVFrame exists), this is a NULL pointer dereference causing an immediate crash. This path executes for every reference frame in the VP9 inter-prediction list whenever `tf.f` is non-NULL, making it reachable by any non-keyframe in a crafted VP9 stream under Vulkan hwaccel.
- **触发条件**: 与上一个漏洞触发条件相同：VP9 inter-predicted 帧 + Vulkan hwaccel 路径 + 至少一个参考帧 `tf.f != NULL` 但 `hwaccel_picture_private == NULL`（可通过残留状态、部分分配失败或 hwaccel 上下文重建后的帧管理缺陷触发）。
- **安全影响**: 进程崩溃（DoS）。现代 Linux 下限于拒绝服务；与第一个漏洞组合可提高触发概率。

<!-- AUDIT_PROMPT_VERSION: 1 -->
