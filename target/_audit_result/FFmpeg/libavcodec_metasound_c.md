After thorough analysis of `metasound.c` and all referenced code paths (twinvq.c, twinvqdec.c, twinvq.h, metasound_data.h), including:

1. **extradata parsing** (lines 279–298): `AV_RL32(extradata + 12)` is guarded by the `extradata_size < 16` check. Mode lookup is a whitelist from static `codec_props[]`; sample_rate, channels, and bit_rate are all fixed by that table.

2. **`add_peak` speech OOB analysis** (lines 38–58): `center` is bounded by `max_period_linear = mtab->size * 0.2 * 6 / isampf`, giving max speech index ≈ `mtab->size / some_mult` (≈256 for 44 kHz). Both buffers—`spectrum[2*channels*mtab->size]` and the shape buffer—are never exceeded given the period/width math.

3. **`read_cb_data` → `ppc_coeffs[60]`**: max `2 * n_div[3]` bytes written is 26 (stereo 44 kHz, ppc_shape_bit=84) — well within 60.

4. **`permut[ftype][pos+j]`** (twinvq.c:208): total elements written ≈ `channels * mtab->size` ≤ 4096 = permut array size. All accessed permut values stay within [0, channels*mtab->size−1] ≤ 4095, and `out` (spectrum) is double-sized so output accesses are also in bounds.

5. **bark1/bark_use_hist/lpc arrays**: all bounded by `TWINVQ_{CHANNELS,SUBBLOCKS,BARK_N_COEF}_MAX` constants which exceed the largest mode parameters.

6. **Bitstream reads**: `window_type` capped at 8 (4-bit field, >8 → error); all `get_bits` width parameters come from static mode tables.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
