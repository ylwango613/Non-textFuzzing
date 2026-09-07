Based on complete analysis of `aacdec_ac.c` and its call chain, here is my final assessment:

**Batch 1 (lines 1–206):** The file implements five functions for USAC arithmetic coding. Key arrays accessed:

- `state->last[512+1]` (513 elements) — written in `ff_aac_ac_map_process` up to index `N/2-1`, read in `ff_aac_ac_get_context` at `i+1`, updated by `ff_aac_ac_update_context` at `idx`.
- Local `last[512]` in `ff_aac_ac_map_process` — memcpy copies 512 bytes from `state->last`; loop reads `last[k]` where `k = i * ratio`.
- CDF tables in `ff_aac_ac_decode` — pointer arithmetic within switch cases for `cdf_len` ∈ {2, 4, 17, 27}.

**Verification of bounds:**

- `N` is always 96, 128, 768, or 1024 (`core_frame_len ∈ {768, 1024}`); `N/2 ≤ 512 < 513`.
- `lg = ics->swb_offset[ics->max_sfb]` with `max_sfb ≤ num_swb` enforced in `setup_sce` (line 1053); `swb_offset[num_swb] = frame_size ≤ 1024`; so `len/2 ≤ 512`.
- In `ff_aac_ac_get_context`: `state->last[i+1]` where `i ≤ len/2-1 ≤ 511` → max index 512. Valid.
- `last[k]` in the resize loop: max `k = (N/2-1) * (last_len/N)`. For worst case `last_len=1024`, `N=96`: `k_max = 47 * 10.67 ≈ 501 < 512`. No OOB.
- `ff_aac_ac_decode` CDF pointer arithmetic: maximum `p-cdf+1` is 16 (cdf_len=17), 3 (cdf_len=4), 26 (cdf_len=27). All accesses `cdf[sym]` and `cdf[sym-1]` stay within the respective table sizes.
- `pki = ff_aac_ac_get_pk(...)` returns values from static lookup tables `ff_aac_ac_lookup_m[742]` (uint8_t). These tables are hardcoded codec data — not attacker-controlled input — so `pki` values are by design valid indices into `ff_aac_ac_msb_cdfs[64]`.
- `coef[2*i+0]` / `coef[2*i+1]` writes: max index `2*(len/2-1)+1 = len-1 ≤ 1023` within the 1024-float `sce->coeffs` buffer. Safe.
- `ff_aac_ac_finish` writes at most to `state->last[512]` (valid).

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
