Having read all 1157 lines of `mediacodecdec_common.c` and the companion `mediacodec_sw_buffer.c` in full, let me summarize the analysis before the final output.

**Batch 1 analysis (lines 1–600):**
- `mediacodec_wrap_sw_audio_buffer` (lines 371–442): `info->size` drives both the modulo alignment check (line 388) and the frame allocation via `nb_samples` (line 396), then `memcpy(frame->data[0], data, info->size)` (line 431). The destination `frame->data[0]` is allocated to exactly `nb_samples * sample_size * nb_channels = info->size` bytes (the modulo check guarantees no remainder), so no write overflow at the destination. The `size` parameter (actual MediaCodec buffer capacity) is passed into the function but never used — if `info->size > size`, this is an OOB read from the platform buffer, which requires Android MediaCodec to mis-report its own buffer sizes; this is a platform trust issue, not an FFmpeg memory-corruption bug.
- Division by zero theoretical case: if `nb_channels = 0` slips through `av_channel_layout_default`, line 388 performs `info->size % 0` (UB/SIGFPE). Relevant only as a DoS, not memory corruption.
- Crop arithmetic at lines 611–613 (`crop_right + 1 - crop_left`) — no overflow guard, but `ff_set_dimensions` → `av_image_check_size2` validates the resulting dimensions and returns an error for out-of-range values.

**Batch 2 analysis (lines 600–1157):**
- Audio format parsing (lines 663–708): `channel_count = 0` is technically possible (key present with value 0, mandatory check only gates key-absent case); downstream arithmetic with `nb_channels = 0` crashes, not memory corruption.
- `ff_mediacodec_dec_send` (lines 898–990): `size = FFMIN(pkt->size - offset, size)` then `memcpy(data, pkt->data + offset, size)` — correctly bounded, no issue.
- `ff_mediacodec_dec_receive` (lines 992–1103): dequeues output buffer, calls into `mediacodec_wrap_sw_buffer` — logic flow is correct.

**sw_buffer.c context:** The `src` pointer computations in all four copy functions add untrusted MediaFormat fields (`info->offset`, `s->slice_height`, `s->stride`, `s->crop_*`) without ever checking against `size`. This can produce OOB READs from the MediaCodec output buffer (not from `frame->data[]`), but (a) these are in `mediacodec_sw_buffer.c`, not the target file, and (b) the destination frame buffers are correctly sized, so no heap WRITE overflow occurs.

**Conclusion:** No externally triggerable memory-*corruption* (heap overflow, OOB write, UAF) vulnerability exists within `mediacodecdec_common.c` that can be triggered by a crafted media file through normal FFmpeg operation.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
