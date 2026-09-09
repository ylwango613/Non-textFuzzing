After exhaustively reading all 1800 lines of `wavpack.c` across multiple passes and cross-referencing `wavpack.h`, here is the summary of what I verified for each critical pattern:

**`value_lookup_buffer` overflow** (lines 664–677): The `total_summed_probabilities > history_bins * MAX_BIN_BYTES` guard fires before any write that would exceed the `MAX_HISTORY_BINS*MAX_BIN_BYTES = 40960`-byte static buffer. Safe.

**`value_lookup[p0][index]` NULL/OOB access** (lines 694, 711–717): Double-guarded: zero `summed_probabilities[p0][255]` returns error before any dereference; `index >= summed_probabilities[p0][255]` returns error before the `value_lookup` read. Safe.

**`memcpy(samples_r, samples_l, bpp * s->samples)`** (line 1693): `s->samples` bounded by `WV_MAX_SAMPLES = 150000`, bpp ≤ 4; frame allocated for exactly `s->samples` samples. Safe.

**`av_fast_malloc(s->samples * stride)`** (line 1641): stride = nb_channels, bounded by `WV_MAX_CHANNELS = 4096`; a prior guard at line 1630 prevents nb_channels = 0. Max product = 614,400,000 — safe for size_t. Safe.

**`s->samples * s->extra_bits << s->stereo_in`** (line 1535): extra_bits ≤ 30 (validated line 1364), stereo_in ∈ {0,1}. Max = 9,000,000. Safe.

**Metadata block parsing / bytestream2**: All byte reads go through bounds-checked `bytestream2_get_*` accessors; block sizes validated against remaining bytes before each sub-block is processed. Safe.

**`decorr->samplesA/B` array indices**: value field masked to [-5, 26]; access patterns for t > 8 use indices 0 and 1; t ≤ 8 uses `j = (pos + t) & 7`; all within `samplesA[MAX_TERM]` = `samplesA[8]`. Safe.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
