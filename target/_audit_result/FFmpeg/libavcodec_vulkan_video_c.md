Having read all 545 lines in full and traced every allocation and data flow:

- All `av_mallocz` calls use sizes derived from `common->nb_mem`, which is set exclusively by the Vulkan driver (`GetVideoSessionMemoryRequirementsKHR`) — a trusted kernel/driver component, not attacker-controlled media-file content.
- The two-call Vulkan idiom (first with NULL to get count, then with array) is implemented correctly: the second call cannot write more entries than allocated because `*pMemoryRequirementsCount` bounds the write.
- `sizeof(T) * nb_mem` multiplications are 64-bit (`sizeof` returns `size_t`; `uint32_t nb_mem` promotes to `size_t`), so no 32-bit integer overflow before `av_mallocz`.
- No `memcpy`/`memmove` calls in the file at all.
- Format-mapping tables are static constants; level/profile converters are pure switch/case with no memory operations.
- DPB image dimensions (`width`, `height`) are stored and passed to `ff_vk_image_create` (another file) but never used for buffer sizing within this file.

No attacker-reachable memory-safety path exists in `vulkan_video.c`.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
