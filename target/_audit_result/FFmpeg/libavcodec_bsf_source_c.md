Having fully analyzed `source.c` (225 lines) and its call chain:

- **`av_bsf_source_add_packet`** (lines 67–116): the `copy` packet is allocated and either ref-copied or move-ref'd from the caller's `pkt`. When `ff_bsf_filter_packet` returns `AVERROR(ENOMEM)` (queue-full path, bitstreamfilter.c:675-676), neither the callee nor the caller frees `copy` → memory leak, but no heap corruption or OOB access.
- **`s->last_pts = pkt->pts + pkt->duration`** (line 80): signed int64 addition that can overflow; result is only used as a PTS hint, not as a size or index → no memory safety impact.
- **`s->warning_limit *= 10`** (line 112): unsigned multiply can eventually wrap to 0, disabling warnings permanently; well-defined unsigned arithmetic, no memory safety impact.
- **`AVERROR(EOF)` vs `AVERROR_EOF`** (line 134): logic bug — returns 1 (positive) instead of an error code — but causes no memory corruption.
- **`avcodec_parameters_copy`** called from `av_bsf_source_parameters_set` and `config_props`: `src->extradata` is copied with `av_mallocz(src->extradata_size + AV_INPUT_BUFFER_PADDING_SIZE)` and `memcpy(dst->extradata, src->extradata, src->extradata_size)` (codec_par.c:120-123). This is internally consistent and the `src` parameters here come from the caller API (not raw untrusted bitstream parsing in this file), so no exploitable heap overflow is introduced in this path.

No memory-safety vulnerability is present in this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
