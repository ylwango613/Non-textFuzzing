I have now read every line of `truespeech.c` (373 lines) and `truespeech_data.h` (160 lines) and traced every critical data-flow path. Here is a complete summary of the verification work:

**`truespeech_place_pulses` — `tmp[7]` / `ts_pulse_values[120]` index analysis**
- `tmp[6 - i]` for i = 0..6: indices 0..6 ✓
- `ts_pulse_scales` index = `pulseoff[q] * 4 + t` ≤ 15×4+3 = 63 < 64 ✓
- Loop 1 (`ptr1 = ts_pulse_values + 30`, j=3): 3 decrements allowed, maximum read index = 90 + i_last ≤ 90+29 = 119 ✓
- Loop 2 (`ptr1 = ts_pulse_values`, j=4): 4 decrements allowed, maximum read index = i_last+60 ≤ 59+60 = 119 ✓
- `ptr2` (into tmp[7]): max 3+4=7 reads, last read is tmp[6] ✓

**`truespeech_apply_twopoint_filter` — `tmp[206]` index analysis**
- `off = av_clip((t/25) + offset1[q>>1] + 18, 0, 145)` → off ∈ [0,145]
- `ptr0 = tmp + 145 - off` → ptr0 ∈ [tmp+0, tmp+127]
- Last iteration (i=59): `ptr0[1]` reads at index (145−off)+60 ≤ 205 ✓
- `ptr1 = tmp+146`; `ptr1[i]` for i=0..59 → indices 146..205 ✓

**`truespeech_synth` — `filters[32]` index analysis**
- `ptr1 = dec->filters + quart * 8`, quart ∈ {0,1,2,3}: max index 24+7 = 31 ✓

**`truespeech_decode_frame` — integer overflow check**
- Guard `if (iterations > INT_MAX / 240)` prevents `iterations * 240` from overflowing ✓
- `samples` advance = `iterations × 4 × 60 = iterations × 240 = frame->nb_samples` ✓

**All codebook accesses** are bounded by the bit-width of the parsed fields (3–5 bits → indices within codebook sizes 8/16/32) ✓

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
