The file is 153 lines. Analysis complete — let me summarize findings:

**`avpriv_mpegaudio_decode_header()` (lines 34–118):**
- `ff_mpa_check_header()` validates header bits before any table access — frequency field `(header>>10)&3` can only be 0,1,2 (3 is rejected), matching `ff_mpa_freq_tab[3]` bounds.
- Redundant but harmless bounds check on line 55 before `ff_mpa_freq_tab[sample_rate_index]`.
- `sample_rate_index` after line 58 adjustment ranges 0–8, matching `[9]`-sized band tables.
- `ff_mpa_bitrate_tab[s->lsf][s->layer-1][bitrate_index]`: all three indices bounded — lsf∈{0,1}, layer-1∈{0,1,2}, bitrate_index∈{1..14} (0 exits early, 15 rejected by header check). Table is `[2][3][15]`.
- No dynamic memory allocation anywhere in this file. No `malloc`, `av_malloc`, `memcpy`, or any heap operation.
- `frame_size` arithmetic cannot overflow to dangerous sizes: max bitrate tab value is uint16_t (≤65535), layer 1 uses `*12000`, layer 2/3 uses `*144000`; with sample_rate minimum 8000 the result fits comfortably in `int`.
- Computed `frame_size` is stored as a plain `int` struct member — no allocation sized by it occurs within this file.

**`ff_mpa_decode_header()` (lines 120–152):** pure wrapper, no allocation, no indexing beyond what's already validated above.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
