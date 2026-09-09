After completing a thorough multi-pass analysis of all 786 lines of `dec.c` plus key dependencies (`parse.c`, `rc.h`, `rc.c`, `celt.h`, `opus.h`, `tab.c`, `parse.h`), I performed the following checks:

**Redundancy fade OOB** (`opus_decode_frame` lines 363–391): writes to `s->cur_out[i] + samples - 120 + delayed_samples` require `samples ≥ 120 - delayed_samples`. Minimum SILK/HYBRID frame at 48 kHz output is 480 samples (NB 10 ms); `delayed_samples` is bounded by ~66 (16-tap filter at 8 kHz→48 kHz). `480 - 120 + 0 = 360 ≥ 0`; no underflow. Similarly for the `redundancy_pos == 1` path: write span is `delayed_samples + 240 ≤ 306 < 480`. Safe.

**`ff_celt_window2[120]` indexing**: `s->redundancy_idx = 120 - delayed_samples`. Since `delayed_samples ≥ 0` (swr_convert never returns more than requested) and `delayed_samples ≤ 66`, `redundancy_idx ∈ [54, 120]`. Accesses to `ff_celt_window2 + redundancy_idx` are in bounds (index ≤ 119 for reads; at 120, loop length `120 - redundancy_idx = 0`, no dereference).

**`redundancy_buf[2][960]` reads**: `ff_celt_decode_frame` with `nb_samples=240` writes at most indices [0, 239]; all reads at `+ 120 + redundancy_idx ≤ +240` are within bounds.

**Packet parsing**: `ff_opus_parse_packet` enforces `frame_count ≤ OPUS_MAX_FRAMES(48)`, `frame_size ≤ OPUS_MAX_FRAME_SIZE(1275)`, total duration `≤ OPUS_MAX_PACKET_DUR(5760)`.

**Extradata parsing**: stream count bounded to [1, 254], channel map byte access validated by `extradata_size < 21 + channels`.

**`sync_dummy[32]` stack buffer**: guarded by `if (out_dummy && sync_size > FF_ARRAY_ELEMS(sync_dummy)) return AVERROR_BUG`.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
