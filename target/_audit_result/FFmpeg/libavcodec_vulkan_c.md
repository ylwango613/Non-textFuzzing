Based on my complete multi-pass analysis of `libavutil/vulkan.c` (all 2899 lines, read in 6 batches), I traced all memory allocation paths, bounds checks, and integer arithmetic:

**Summary of findings:**

1. **Wrong null-check at line 255** (`if (!s->qf_props)` instead of `if (!s->query_props)`) — a logic bug that would dereference a NULL `query_props` under OOM, but requires system memory exhaustion to trigger, not a crafted media file.

2. **Fixed-size stack arrays in `ff_vk_map_buffers` / `ff_vk_unmap_buffers`** (`inval_list[64]` / `flush_list[64]`) — no bounds check before writing, but every caller in the codebase uses the inline wrapper with `nb_buffers = 1`; practically unreachable with a count > 64.

3. **All other allocation paths** (`av_realloc` for host image layouts, `av_calloc` for qf_props/video_props, etc.) — sized from GPU driver-reported counts, not from parsed media bytes; no attacker-controlled overflow paths.

None of the bugs are reachable through a crafted media file. The entire file is Vulkan GPU-resource-management infrastructure (command pools, semaphores, shader compilation), not media container or codec parsing. The attack surface here is the GPU driver/runtime, not the media bitstream.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
