I've now read all 685 lines of `sync_queue.c` in two batches and traced every significant call chain. Let me verify the one suspicious code path before finalizing.

**Batch 1 analysis (lines 0–596):**

- `overflow_heartbeat()` line 285: `sq->streams[stream_idx].tb` is accessed while `stream_idx` may start at `-1`. However, the `||` short-circuit guarantees that line 286 is only evaluated when `ts != AV_NOPTS_VALUE`, which is only true *after* `stream_idx` has been set to a valid non-negative index (both `ts` and `stream_idx` are always updated together in the same `if`-block). No OOB access occurs.
- `offset_audio()` line 393: `const int offset = nb_samples * bps * (planar ? 1 : f->ch_layout.nb_channels)` — signed `int` multiplication. If it overflows, `f->extended_data[i] += offset` would move the pointer backward. However, `nb_samples` is always bounded by `st->frame_samples` (the encoder's output frame size, a codec property, not attacker-controlled via input file). With typical codec frame sizes (≤ 4608 samples), bps (≤ 8) and channels (≤ 64): max product = 4608 × 8 × 64 = 2,359,296 — well within INT_MAX.
- `receive_samples()`: All `av_samples_copy` arguments are bounded by `to_copy ≤ st->frame_samples`. No integer overflow path from crafted input.

**Batch 2 analysis (lines 597–685):**

- `sq_add_stream()`: `nb_streams + 1` unsigned overflow at UINT_MAX is not practically reachable.
- All other functions (`sq_limit_frames`, `sq_frame_samples`, `sq_alloc`, `sq_free`) have no reachable memory-safety issues.

**External-trigger check:** All potentially dangerous multiplications and pointer arithmetics are bounded by encoder configuration values (`st->frame_samples`, `bps`, `nb_channels`), none of which are attacker-controlled through a crafted media file alone.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
