I now have the complete picture. Let me consolidate all the findings from my analysis of both `libavcodec/subviewerdec.c` and `libavformat/subviewerdec.c` and their full call chains.

**Summary of analysis:**

1. **`subviewer_event_to_ass` `while (*p)` loop** — relies on null-termination of `avpkt->data`. Packets are created via `ff_subtitles_queue_insert` → `av_new_packet` (which calls `packet_alloc` doing `memset(buf+size, 0, AV_INPUT_BUFFER_PADDING_SIZE)`) or `av_grow_packet` (which does `memset(pkt->data + pkt->size, 0, AV_INPUT_BUFFER_PADDING_SIZE)` at line 167). Zero-termination is guaranteed. **Not vulnerable.**

2. **`p[1]` access when `p[0] == '\n'`** — `p[0]` is `'\n'` (non-null, loop invariant), and `p[1]` is either another data byte or the null byte in the padding area — both valid allocated memory. **Not vulnerable.**

3. **`strncmp(p, "[br]", 4)` near end-of-string** — reads up to 4 bytes of `p` including any null terminator in the padding. All accesses are within allocated memory. **Not vulnerable.**

4. **`p += 4` after a `strncmp` match** — only advances when all 4 bytes match `[br]`; padding ensures the resulting pointer is still safe. **Not vulnerable.**

5. **Stack buffers `key[32]`, `value[128]` in demuxer** — loop bounds `i < sizeof(key)-1` and `j < sizeof(value)-1` strictly prevent overflow. **Not vulnerable.**

6. **`read_ts` integer mismatch (`int` variables with `%u`)** — produces wrong timestamp arithmetic but does not drive any allocation size or buffer index. **Not a memory-safety issue.**

7. **`ff_subtitles_queue_insert` with `strlen(line)`** — `line` is at most 2047 bytes (bounded by `ff_get_line(..., 2048)`); `av_new_packet` / `av_grow_packet` handle this safely. **Not vulnerable.**

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
