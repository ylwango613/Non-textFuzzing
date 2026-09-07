I have now read all 2834 lines of `ffmpeg_sched.c` across six batches, traced all allocation calls (`GROW_ARRAY`, `av_calloc`, `av_malloc_array`, `av_mallocz`), followed the `grow_array` implementation, and searched for all `av_malloc`, `memcpy`, `pkt->size`, and `pkt->stream_index` usages.

**Analysis summary per group:**

- **Lines 1–500 (structs, waiter, queue_alloc, task helpers):** All allocations use `tq_alloc` internally; queue_size is bounded by the constant `DEFAULT_FRAME_THREAD_QUEUE_SIZE`. No attacker-controlled sizes.

- **Lines 500–1000 (sch_free, sch_add_* registration):** All dynamic arrays grow via `GROW_ARRAY` → `grow_array()`, which has an explicit `new_size >= INT_MAX / elem_size` overflow guard before calling `av_realloc_array`. The element counts are bounded by the number of codec/stream objects in the transcoding graph, not by values read from the media file bytestream.

- **Lines 1000–1500 (sch_connect, schedule_update, choke/unchoke):** `check_acyclic_for_output` allocates `filters_stack` with `av_malloc_array(nb_filters, ...)` and guards the push with `av_assert0(nb_filters_stack < sch->nb_filters)` — no OOB. Logic bug noted in `choke_demux`/`unchoke_downstream` (only first destination per stream is processed), but this is a scheduling correctness issue, not a memory-safety bug.

- **Lines 1500–2000 (mux_queue_packet, send_to_enc_sq):** `mux_queue_packet` computes `2 * packets` (size_t). If this wrapped, the subsequent `new_size <= packets` check would trigger the error path — not a memory-safety bypass. `send_to_enc_sq` accesses `sq->enc_idx[ret]` where `ret` is an internal sync-queue stream index bounded by the number of streams registered in the sync queue, which is an internal invariant not directly attacker-controlled from a media file.

- **Lines 2000–2834 (send/receive path, task teardown):** All array accesses (`dst_finished[i]`, `outputs[i]`, etc.) are bounded by counters that match the allocation sizes from `start_prepare`. `pkt->stream_index` is validated against `d->nb_streams` via `av_assert0` (line 2196).

**Key structural observation:** `ffmpeg_sched.c` is a pure threading/IPC orchestration layer. It never reads data directly from a media file bytestream. All `AVPacket`/`AVFrame` objects that flow through it are already parsed by `libavformat`/`libavcodec`. The memory-safety attack surface of this file is effectively zero with respect to crafted media input.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
