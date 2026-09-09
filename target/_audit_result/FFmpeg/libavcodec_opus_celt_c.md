I've now performed a thorough multi-pass analysis of the complete 484-line `celt.c` and its full call chain (dec_celt.c, pvq.c, celt.h, tab.c, parse.c, dec.c). Let me document the key findings from each area examined:

**Group 1 (celt.c lines 28-133, `ff_celt_quant_bands`):**
- `norm1[2*8*100]` = 1600 floats; `norm2 = norm1+800`. Maximum `band_offset+band_size = ff_celt_freq_bands[21]<<3 = 800`, which lands exactly at norm1[799] (valid). No overflow.
- `lowband_scratch[8*22]` = 176 floats; maximum write is `ff_celt_freq_range[20]<<3 = 176` – exactly at the boundary, no overflow.
- `while (ff_celt_freq_bands[--foldstart] > effective_lowband)` terminates at foldstart=0 because effective_lowband ≥ ff_celt_freq_bands[start_band] ≥ 0 = ff_celt_freq_bands[0], preventing underflow to index -1.
- `collapse_masks[CELT_MAX_BANDS=21]` accessed at j ≤ end_band−1 ≤ 20 – within bounds.

**Group 2 (celt.c lines 137-484, `ff_celt_bitalloc`):**
- Division at line 350: `remaining / (ff_celt_freq_bands[j+1] − ff_celt_freq_bands[start_band])` – denominator always ≥ 1 because `j > skip_startband ≥ start_band`, and `ff_celt_freq_bands` is strictly increasing.
- `ff_celt_log2_frac[24]` accesses: max index = end_band−start_band ≤ 21, and j−start_band ≤ 20, both < 24.
- `ff_celt_static_alloc[11][21]` and `ff_celt_static_caps[4][2][21]`: all indices from validated f->size∈[0,3], channels∈{1,2}, band∈[0,20].
- The `start_band==end_band==0` case would trigger division-by-zero at line 350 (j=−1, denominator=0), but this is unreachable in practice: actual Opus decoding always has end_band ∈ {13,17,19,21} from `ff_celt_band_end[bandwidth]`.

**Group 3 (pvq.c, `quant_band_template`):**
- `pvq->qcoeff[256]` and `pvq->hadamard_tmp[256]`: maximum N = 176 < 256 at all recursion depths.
- `ff_celt_hadamard_order[46]` access: maximum index = 30+15 = 45 (identity order for stride=16, longblocks=0) or 6+7=13 (hadamard-8). Both < 46 – no OOB.
- `lowband_scratch=NULL` passed to Y-half recursive call: potential null-ptr write gated by `if (!stereo && level == 0)` check, which is never true for Y-half (level = parent_level+1 ≥ 1).
- `lowband_out` writes from pvq are bounded to N0 = band_size elements, kept within norm1/norm2 arrays.

**Conclusion:** After exhaustive analysis of `celt.c` and its complete call chain, no externally-triggerable memory safety vulnerability was found. All buffer accesses, integer arithmetic, and recursive depth are tightly bounded by validated stream fields and fixed table sizes. The code is memory-safe against crafted Opus packets on this code path.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
