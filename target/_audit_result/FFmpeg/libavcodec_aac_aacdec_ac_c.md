Based on my complete analysis of `aacdec_ac.c` and its full call chain:

**Analysis summary:**

1. **`state->last[513]` array bounds** — All loops (`ff_aac_ac_map_process`, `ff_aac_ac_get_context`, `ff_aac_ac_update_context`, `ff_aac_ac_finish`) access at most index 512. For N = 1024 (max valid value, set from a 3-bit config field to 768 or 1024), N/2 = 512 ≤ 512. Validated.

2. **Local stack buffer `last[512]`** — Read at index k = `(int)(i * ratio)` where ratio = `state->last_len / N`. For all valid last_len ∈ {96, 128, 768, 1024} and N values, max k stays < 512. Validated with all pairwise combinations.

3. **`ff_aac_ac_decode` pointer bounds** — For cdf_len=17 (msb), max p_offset = 15 → sym max = 16 → cdf[16] valid. For cdf_len=4 (lsb), max p_offset = 2 → sym max = 3 → cdf[3] valid. Neither caller can trigger case 2/27.

4. **Lookup table `pki` bounds** — `ff_aac_ac_lookup_m[]` is a hardcoded table whose values max at 0x3F = 63, within `ff_aac_ac_msb_cdfs[64]`. Not user-controlled.

5. **`lg = ics->swb_offset[ics->max_sfb]`** — `max_sfb` is validated against `num_swb` (line 1053–1059 in `aacdec_usac.c`) before `decode_spectrum_ac` is called. `swb_offset` is from static codec tables, max 1024.

6. **Signed integer overflow in `rng * cdf[sym-1]`** — UB in C but no buffer-access consequence; pointer advancement is structurally bounded by the switch-case logic.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
