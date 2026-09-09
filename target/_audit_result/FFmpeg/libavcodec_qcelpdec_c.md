Verified: `g1[i]` accesses on `qcelp_g12ga` (61 entries, index 0–60):
- RATE_FULL i=3,7,11,15 (adjustment path): `cbgain[3,7,11,15]` are 3-bit fields → `g1[i] ≤ 28 + 32 = 60` ✓  
- RATE_HALF/QUARTER: `q->bitrate == RATE_FULL` is false, no adjustment added, 4-bit cbgain → `g1[i] ≤ 60` ✓  
- RATE_OCTAVE: `g1[0] = 2*(2-bit cbgain) + av_clip(..., 0, 54) ≤ 6+54 = 60` ✓  
- I_F_Q: `g1[0] = prev_g1[1] - [0..6], clamped ≥ 0, max 60` ✓

All `qcelp_lspvq[i][lspv[i]]` accesses bounded by bit widths of bitmaps (6-bit→64 entries, 7-bit→128 entries). `do_pitchfilter` lag range validated (pfrac+plag ≥ 124 check). `rnd_fir_filter_mem[180]` usage (20+8×20=180) correct. `formant_mem[170]` accessed at +10..+169. All memory region accesses safe.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
