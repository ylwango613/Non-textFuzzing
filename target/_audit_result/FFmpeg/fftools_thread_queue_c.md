Now I have a complete picture. Let me finalize the analysis.

**Key observations from the full read:**

- `thread_queue.c` (269 lines, fully read in one pass)
- All `tq->finished[stream_idx]` accesses are guarded by `av_assert0(stream_idx < tq->nb_streams)` before use (lines 122, 229, 245)
- `av_calloc(nb_streams, sizeof(*tq->finished))` — `av_calloc` internally checks for integer overflow; safe
- `tq->fifo_stream_index` is a fixed-capacity circular buffer (no auto-grow); `tq->fifo` (container fifo) has `AV_FIFO_FLAG_AUTO_GROW` (confirmed in `container_fifo.c` line 83)
- The send path (lines 139–145) writes to `fifo_stream_index` first, then to `fifo`. If `av_container_fifo_write` fails after `av_fifo_write` succeeds, an orphaned stream-index entry is left, causing a logical desync (wrong stream-index returned to consumer). However, all stream-index values stored are pre-validated integers < `nb_streams`, so the subsequent `tq->finished[idx]` access stays in-bounds even with the desync. Data objects are moved, not aliased; `av_frame_unref`/`av_packet_unref` are idempotent — no double-free or UAF results
- The `av_assert0(ret >= 0)` on line 169 cannot be violated: `fifo_stream_index` always has ≥ as many entries as `fifo` (index is written before data), so the consumer reads always find a valid index entry whenever a data entry is present
- All allocation sizes are computed by `av_calloc`/`av_fifo_alloc2`/`av_realloc_array` with built-in overflow protection
- No fixed-size stack buffers, no `memcpy` with attacker-controlled sizes, no unchecked pointer arithmetic

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
