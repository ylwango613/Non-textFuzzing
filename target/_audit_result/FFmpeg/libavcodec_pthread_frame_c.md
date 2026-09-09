I have now fully read the 1105-line file in two batches and traced all memory allocation sites, size computations, and `memmove`/`memcpy` calls. Let me summarize each critical area:

**`decoded_frames_get_free` (lines 188–207):** `av_realloc_array(df->f, df->nb_f + 1, sizeof(*df->f))` — `av_realloc_array` internally calls `size_mult` (confirmed from `mem.c:220`) which detects `nmemb × size` overflow and returns NULL. No issue.

**`decoded_frames_pop` (lines 210–215):** `memmove(df->f, df->f+1, (df->nb_f - 1) * sizeof(*df->f))` — `nb_f` is `size_t`; if zero this underflows to `SIZE_MAX`. However the only call site (line 609–610) is inside `if (fctx->df.nb_f)`, so `nb_f > 0` is guaranteed. No externally-reachable underflow.

**`update_context_from_thread` (lines 342–451):** `av_mallocz(hwaccel->priv_data_size)` — size comes from a compiled-in `FFHWAccel` struct, not external media data. `av_channel_layout_copy`, `av_buffer_ref` are all safe wrappers.

**`init_thread` (lines 812–908):** `av_memdup(avctx, sizeof(*avctx))` (fixed size), `av_mallocz(codec->priv_data_size)` (codec constant), `av_packet_alloc()` (fixed) — no externally-controlled sizes.

**`ff_frame_thread_init` (lines 910–971):** `av_calloc(thread_count, sizeof(*fctx->threads))` — `thread_count` is bounded by `MAX_AUTO_THREADS`, not by media input.

**`ff_thread_report_progress`/`ff_thread_await_progress`:** `progress[field]` where the array is `atomic_int progress[2]`. The `field` parameter is always 0 or 1 in all callers (confirmed by grep); it's a codec-internal constant, not derived from media file content.

**`ff_thread_sync_ref` (lines 1075–1093):** `offset` is an `offsetof()` value from codec internals; not externally controlled.

This file is pure threading infrastructure. No memory allocation here takes size from untrusted external (container/media) data. All unsafe patterns are either guarded by callers or impossible to trigger from crafted media input.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
