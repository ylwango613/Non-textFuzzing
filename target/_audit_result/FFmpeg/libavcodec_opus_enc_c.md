After thorough multi-pass reading of all 765 lines of `enc.c` plus the supporting headers (`enc.h`, `celt.h`, `opus.h`, `enc_psy.h`) and key sections of `enc_psy.c`, here is the complete picture of findings:

**Batch 1 (lines 1–300):** All `memcpy`/`memset` into `b->overlap` and the scratch buffer in `celt_frame_mdct` are correctly bounded. `b->overlap` is 128 floats (FFALIGN(120,16)); maximum write is 120 floats. The scratch pointer arithmetic (`win=scratch`, `temp=scratch+1920`) plus `memset(win, 0, wlen*sizeof(float))` where `wlen ≤ OPUS_BLOCK_SIZE(4)=1920 ≤ 2048` (the scratch size) stays within bounds. `f->size` is capped at `CELT_BLOCK_960=3` by the psyctx.

**Batch 2 (lines 301–600):** The `left = (subframesize - cur->nb_samples)*bps` pattern (line 162) involving a `size_t` computation could theoretically wrap to a giant value if `cur->nb_samples > subframesize`, producing a catastrophic `memset`. However, the encoding framework enforces input frame sizes via `AV_CODEC_CAP_SMALL_LAST_FRAME` (only *shorter* last frames allowed, never larger), and `ff_bufqueue` entries originate only from validated input frames — this condition is not externally triggerable through a crafted media file in a standard `ffmpeg -i` transcoding pipeline.

**Batch 3 (lines 600–765, init):** `max_frames = ceilf(FFMIN(max_delay_ms,120)/2.5)` and the psyctx `s->p.frames` share the same `max_delay_ms`-derived bound. Cross-checking `flush_silent_frames()` confirms `s->p.frames ≤ (48×120)/packet_samples` ≤ `max_frames` for all reachable encoder states.

**Array-index check on `toc_cfg`:** All three indices (`packet.framesize ≤ 3`, `mode = OPUS_MODE_CELT = 2`, `bandwidth = OPUS_BANDWIDTH_FULLBAND = 4`) are within the `[6][3][5]` table bounds.

**Logic bugs found but not memory-safety:** wrong memset base offset for `sf > 0` subframes (line 164–165, within-bounds corruption); operator precedence bug in `write_opuslacing` line 504 (`v - dst[0] >> 2` instead of `(v - dst[0]) >> 2`); `celt_enc_quant_pfilter` always loops over 2 blocks even in mono mode (struct always has `block[2]`, no OOB).

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
