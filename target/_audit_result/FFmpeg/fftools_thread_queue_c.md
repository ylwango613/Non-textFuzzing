`av_assert0` is confirmed **always-on** (unconditional `abort()`, not gated by NDEBUG). All bounds checks are always enforced.

Complete analysis of `thread_queue.c` (269 lines, all read):

**`tq_alloc()` (lines 72–115):** `av_calloc(nb_streams, sizeof(*tq->finished))` — safe, `av_calloc` has internal overflow protection. `av_fifo_alloc2(queue_size, sizeof(unsigned), 0)` — `queue_size` is a `size_t`, no overflow path.

**`tq_send()` (lines 117–154):** `av_assert0(stream_idx < tq->nb_streams)` is always-on. FIFO write order: `fifo_stream_index` first, `fifo` second. If `av_container_fifo_write()` fails, `fifo_stream_index` has a stale entry — a logic desync — but since `stream_idx` was already validated before writing, stale entries are always within `[0, nb_streams)`. No OOB possible.

**`receive_locked()` (lines 156–195):** Reads from `fifo` then `fifo_stream_index`. `av_assert0(ret >= 0)` ensures the pairing can't silently break. `idx` used at `tq->finished[idx]` always came from `tq_send()` which validated it; no external file bytes control this value directly.

**`tq_send_finish()` / `tq_receive_finish()` (lines 227–256):** Both guard with `av_assert0(stream_idx < tq->nb_streams)`.

**Key finding:** This file is an internal threading utility — no bytes from a crafted media file reach `stream_idx` or any of the FIFO indices directly. Stream indices come from FFmpeg's demuxer layer, which is already tracked separately. No `malloc`/`memcpy` with attacker-controlled sizes, no pointer arithmetic, no buffer reads from external data.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
