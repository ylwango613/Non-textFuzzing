After thoroughly reading `acelp_vectors.c` (266 lines) and tracing its complete call chain through `amrnbdec.c`, `g729dec.c`, `sipr16k.c`, and `wmavoice.c`, I find:

**Group 1 — Static tables (lines 31–115):** All constant lookup tables. No dynamic data.

**Group 2 — `ff_acelp_fc_pulse_per_track` (lines 117–139):** The index `fc_v[i + tab1[pulse_indexes & mask]]` uses codec-internal tables. For G.729@8k: bits=3, pulse_count=3, tab1 max=35, i max=2 → max index=37 well within SUBFRAME_SIZE=80. For G.729@6.4k: pulse_count=1, tab1 max=38 → max 38, safe. The final `fc_v[tab2[pulse_indexes]]` after right-shifting by `pulse_count*bits` bits stays within tab2 bounds because bitfield sizes (13-bit and 9-bit) are exactly sized for the shift residuals.

**Group 3 — `ff_decode_10_pulses_35bits` (lines 141–160):** Accesses `fixed_sparse->x[2*i+1]` up to index 9. All callers hardcode `half_pulse_count=5`, so max index=9 exactly fits `x[10]/y[10]`.

**Group 4 — `ff_set_fixed_vector` (lines 224–241):** Has `av_assert0(x < size)` which is **always enabled** (not ASSERT_LEVEL-gated) and calls `abort()`. This does NOT check `x >= 0`. However, all call sites compute x from non-negative bitmasked values (WMAVoice: `n + 5*pos1` ≥ 0; AMR NB: `(bits & mask)*5 + offset` ≥ 0).

**Group 5 — `ff_clear_fixed_vector` (lines 243–256):** No bounds check for initial x value, but always invoked after `ff_set_fixed_vector` which aborted on invalid x; x values are unchanged between the two calls.

**Conclusion:** No externally-triggerable memory safety vulnerabilities exist in this file. All buffer access offsets are either bounded by codec-internal constants, masked bitfield values, or unconditional `av_assert0` guards that cause abort before any out-of-bounds write.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
