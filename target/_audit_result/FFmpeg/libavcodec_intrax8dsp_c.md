After thorough analysis of `intrax8dsp.c`, all related headers, and the calling code in `intrax8.c`, I can confirm:

- The `scratchpad[42]` buffer is the destination for all DSP writes. The maximum offset written is `area6 + 7 = 33 + 7 = 40`, and the buffer is 42 bytes — no overflow possible.
- All spatial compensation functions (`spatial_compensation_0` through `spatial_compensation_11`) read from `src` (the scratchpad) at offsets bounded by compile-time constants (area definitions, fixed 8×8 loop limits). The largest read is `src[area4 + 11] = src[28]`, well within bounds.
- The `x8_loop_filter` operates on frame pixel data with fixed ±5/+4 stride offsets; edge guards (`edges & 1`, `edges & 2`) prevent application at frame boundaries where the neighborhood pixels would be invalid.
- No dynamic allocation, no user-controlled sizes used as array indices, no integer overflow paths.
- `w->orient` is bounded to [0,11] by data-flow logic (not just assertions), so the `spatial_compensation[w->orient]` dispatch is safe.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
