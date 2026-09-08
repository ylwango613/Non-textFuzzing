I have now completed my full analysis of all 2464 lines of `dca_core.c`. Below is a summary of the key areas examined and why each is safe:

1. **`alloc_sample_buffer` / `alloc_x96_sample_buffer`**: `nframesamples` = (DCA_ADPCM_COEFFS=4 + npcmblocks≤128) × DCA_CHANNELS(7) × DCA_SUBBANDS(32) = 132×7×32 = 29,568 — no integer overflow, fits comfortably in `int`.

2. **`parse_aux_data` prim_dmix_coeff write**: `m = ff_dca_dmix_primary_nch[prim_dmix_type] ≤ 4`, `n = ff_dca_channels[audio_mode≤9] + !!lfe_present ≤ 5+1 = 6`; `m×n ≤ 24 = DCA_DMIX_CHANNELS_MAX × DCA_CORE_CHANNELS_MAX`, array is exactly 24 entries — no OOB.

3. **XXCH downmix coefficient array**: `xxch_dmix_coeff[2×6=12]`, masked to subset of `xxch_core_mask` (≤6 bits set) across ≤2 channels — total writes ≤12, exactly matches array size.

4. **XBR subframe channel/band indexing**: `xbr_bit_allocation[DCA_CHANNELS][DCA_SUBBANDS]`, `xbr_nsubbands[32]`, all bounded by condition `xbr_base_ch + xbr_nchannels[i] ≤ s->nchannels ≤ 7`.

5. **X96 subband extension**: `nsubbands[ch]` set to 32–64 in X96 context; `scale_factors[ch][band>>1][band&1]` has `band>>1 ≤ 31`; `x96_subband_samples[7][64]` correctly sized; `bit_allocation[7][64]` handles band<64.

6. **LFE sample buffer**: Total LFE samples bounded by `npcmblocks/2` via subframe overflow check; buffer allocated as `DCA_LFE_HISTORY + npcmblocks/2` — exact fit.

7. **`joint_intensity_index` accesses**: Both CORE and X96 paths validate `n ≤ nchannels` before storing; `src_ch = n-1` then accesses `nsubbands[src_ch]` where src_ch ≤ 6 < DCA_CHANNELS(7).

8. **`parse_scale` / `parse_joint_scale`**: Negative `scale_index` handled via unsigned cast comparison; out-of-range always rejected before table lookup.

9. **`(1U << spkr)` in ch_mask loops**: DCA_SPEAKER_COUNT = 32; all speaker enum values 0–31, no UB.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
