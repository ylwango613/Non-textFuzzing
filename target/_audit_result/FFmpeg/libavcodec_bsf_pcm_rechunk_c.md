Based on my thorough analysis of `pcm_rechunk.c` (241 lines), here is what I verified:

**`init()` lines 49-58**: `sample_size = nb_channels * bps / 8`. For all listed codec_ids, `bps` is ≥ 8, so `sample_size ≥ 1` for valid `nb_channels`. The check at line 57 (`min_samples > INT_MAX / s->sample_size - 1`) guards against `data_size = nb_samples * sample_size` overflowing in `rechunk_filter()`.

**`rechunk_filter()` lines 127-128**: `data_size = nb_samples * s->sample_size`. In non-frame-rate mode `nb_samples = nb_out_samples`, bounded by init() check. In frame-rate mode, per-frame sample count is within ±1 of `min_samples` (Bresenham distribution), and the `- 1` slack in the init() check explicitly covers this ceiling.

**`memcpy` at line 145**: `drain = FFMIN(in_pkt->size, data_size - out_pkt->size)`. The invariant `out_pkt->size ≤ data_size` is maintained throughout; `in_pkt->size` is non-negative; so `drain ≥ 0` always. The write stays within the `data_size`-byte allocation.

**`set_silence` at line 173**: Writes `data_size - out_pkt->size` bytes starting at `out_pkt->data + out_pkt->size`. Both `s->n` (which drives `data_size`) and the allocation are consistent within a single packet's lifetime. No OOB.

**`av_new_packet` with negative `data_size`**: `packet_alloc()` checks `size < 0` (line 86 of packet.c) and returns `AVERROR(EINVAL)`, which is propagated correctly at lines 136-138.

**`drain_packet(..., drain / s->sample_size)`**: Division is safe because `sample_size ≥ 1` for all codecs in the supported list under realistic `nb_channels` values.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
