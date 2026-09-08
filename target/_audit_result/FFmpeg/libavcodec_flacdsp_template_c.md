After thorough analysis of `flacdsp_template.c` and its complete calling chain through `flacdec.c`, I find no exploitable memory-safety vulnerabilities:

- **`channels`** passed to all decorrelate functions comes from the frame header and is validated in `flac.c` to be 1–8 (`FLAC_MAX_CHANNELS`). `s->decoded` is sized to `FLAC_MAX_CHANNELS`, so `in[i]` accesses are always in-bounds.
- **`len`** is `s->blocksize`, which is checked at `flacdec.c:652–656` to not exceed `s->stream_info.max_blocksize`. Buffers are allocated for exactly `max_blocksize` samples per channel.
- **`shift`** is `32 - bps` or `16 - bps`, always in `[0, 31]`. The left-shift `(unsigned)in[i][j] << shift` is defined because both operand and shift are unsigned and shift < 32.
- For non-planar output, `out[0]` is allocated by `ff_thread_get_buffer` for `nb_samples * channels * bytes_per_sample` bytes, matching the `len * channels` writes.
- For planar output, `out[c]` for `c < channels ≤ 8` maps to `frame->data[c]`, all set by `ff_thread_get_buffer` (8 slots available via `AV_NUM_DATA_POINTERS`).
- The `ls_c`/`rs_c`/`ms_c` variants are only dispatched when `ch_mode` indicates a 2-channel side mode, so their hard-coded accesses to `in[0]` and `in[1]` are always safe.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
