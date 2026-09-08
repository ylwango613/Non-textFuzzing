I've now completed a full audit of `dynamic_hdr_vivid.c` and all related struct definitions. My analysis:

**Issue 1 (line 125):** The bounds check `get_bits_left(gb) < 3 + params->color_saturation_num * 8` uses `color_saturation_num` *before* reading it from the bitstream (which happens on line 128). This is a logic bug — the check is effectively `< 3` when the struct is zero-initialized. However, the subsequent field read is a 3-bit value (range 0–7), and `color_saturation_gain` is declared with 8 elements, so the loop indices 0–6 are always within bounds. No OOB write.

**Issue 2 (line 101):** The check `get_bits_left(gb) < 1 + tm_params->three_Spline_num * 43` similarly uses the stale (zero) `three_Spline_num` before the 1-bit read on line 103. After reading, `three_Spline_num` ∈ {1, 2}. There is also an explicit `FF_ARRAY_ELEMS` guard on line 104, and `three_spline[2]` has exactly 2 elements. No OOB write.

**Conclusion:** Both are logic correctness bugs (the bounds checks don't actually validate what they claim to), but neither results in a memory safety violation. The array sizes in the structs (`color_saturation_gain[8]`, `three_spline[2]`, `tm_params[2]`, `params[3]`) are all large enough to accommodate the maximum values derivable from the fixed-width bit fields. `GetBitContext` reads past the buffer end return 0 rather than causing memory corruption.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
