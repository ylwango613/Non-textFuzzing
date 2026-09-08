Based on my complete multi-pass analysis of the full 2029-line `libavformat/flvdec.c` and the 123-line `libavcodec/flvdec.c`, including tracing all allocation helpers, size-accounting chains, and array-bounds logic:

- **`parse_keyframes_index`**: `arraylen>>28` caps allocation at ~2 GB (no overflow on 64-bit; malloc fails safely on large values, handled at line 573).
- **`flv_queue_extradata`**: `size` parameter is always `track_size ≥ 0` (enforced by checks at lines 1781 and 1844 before any call site); `ff_alloc_extradata` itself guards `size < 0`.
- **`flv_parse_mod_ex_data`**: `ex_size` bounded 1-65536; guard `ex_size >= *size` prevents OOB allocation and read.
- **`flv_read_packet` size accounting**: negative-size paths caught at lines 1568 and 1781 before any memory is allocated or written.
- **`new_extradata[]` indexing**: `stream_type` is always 0-3 (within `[FLV_STREAM_TYPE_NB]`); multitrack uses `av_realloc_array` growing correctly.
- **`resync_buffer`**: dual-copy ring-buffer math and `lsize2 + 8 < FFMIN(i, RESYNC_BUFFER_SIZE)` ensure all accesses stay within the 2 MB buffer.
- **AMF recursion**: `depth > MAX_DEPTH` (16) prevents unbounded stack growth; all string reads use bounded buffers.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
