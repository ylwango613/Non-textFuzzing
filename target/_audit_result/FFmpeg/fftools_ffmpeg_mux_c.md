Now I have the key data. Let me verify the `desc[]` vs `wallclock[]` sizes precisely:

- `fd->wallclock[LATENCY_PROBE_NB]` — array size = `LATENCY_PROBE_NB` = 7 (indices 0–6)
- `desc[]` initializer uses `[LATENCY_PROBE_NB]` = "mux" as the last entry → array size = `LATENCY_PROBE_NB + 1` = 8 (indices 0–7)
- Inner loop: `next <= FF_ARRAY_ELEMS(fd->wallclock)` = `next <= 7` → max `next` = 7
- At `next = 7 = LATENCY_PROBE_NB`: `val_next = now` (guarded), `desc[7]` = "mux" — valid, no OOB

The `sch_stream_idx[stream_idx]` access (line 428–429): `stream_idx` only has a lower-bound check (`< 0`), and no upper-bound check against `mux->nb_sch_stream_idx`. However, this index is set by the internal scheduler (`sch_mux_receive`), not derived from media file content — the scheduler allocates exactly as many entries as registered streams and sets `stream_index` within that range as an invariant.

The file is the mux **output** path — it operates on data already validated and produced by the internal encoding/filtering pipeline. No code in this file parses attacker-controlled byte streams (chunk sizes, nb_entries, extradata, etc.) from a container format. All externally-controlled parsing happens upstream in demuxers and decoders, not here.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
