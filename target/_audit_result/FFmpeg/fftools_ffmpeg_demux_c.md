After a comprehensive multi-pass review of all 2584 lines of `ffmpeg_demux.c`, I examined:

**Group 1 (lines 1–500)**: Timestamp arithmetic, `ts_fixup`, `pts_wrap_bits` shift (line 422 requires `< 64` but not `> 0`, so `1LL<<(0-1)` is UB — but it requires a user-set `copy_ts` flag and doesn't lead to memory corruption).

**Group 2 (lines 500–1000)**: Demux send/BSF pipeline, BSF flush, `input_thread` main loop. The `report_new_stream` at line 204 performs the array dereference `d->f.ctx->streams[pkt->stream_index]` **before** the bounds check at line 206. However, libavformat guarantees `nb_streams` is updated before `av_read_frame` returns, so the access is safe in practice.

**Group 3 (lines 1000–1500)**: `ifile_close`, `ist_use`, decoder init, `avcodec_parameters_copy` at line 1870 — copies from a stream correctly allocated by the demuxer; no size arithmetic issue here.

**Group 4 (lines 1500–2000)**: `ist_add` parsing of codec/BSF options. At lines 1999–2003 (`istg_parse_tile_grid`):
```c
opts.crop_bottom = tg->coded_height - tg->height - tg->vertical_offset;  // int arithmetic → unsigned
opts.crop_right  = tg->coded_width  - tg->width  - tg->horizontal_offset;
```
When the attacker-controlled `int` arithmetic is negative, wrapping to `UINT_MAX` occurs. However, these values are subsequently formatted via `snprintf(crop_buf, 64, "…%u…")` — `snprintf` safely truncates, and the crop filter rejects invalid specs with `AVERROR(EINVAL)`. No heap corruption results.

**Group 5 (lines 2000–2584)**: `ifile_open` initialization. All `avformat_open_input` / `avformat_find_stream_info` / `ist_add` calls are well-guarded. `avformat_seek_file` arithmetic is safe (constants clamped to `INT64_MIN`/`INT64_MAX`). Crop buffer in `ffmpeg_filter.c:1732` is 64 bytes with `snprintf` — worst-case 82-char output is truncated, not OOB.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
