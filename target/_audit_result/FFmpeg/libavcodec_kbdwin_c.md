Based on my analysis of `kbdwin.c`:

- `temp[]` is a stack array of size `FF_KBD_WINDOW_MAX / 2 + 1` = 513 elements
- `av_assert0(n <= FF_KBD_WINDOW_MAX)` is **always-on** (not NDEBUG-gated) — calls `abort()` unconditionally before any OOB write could occur
- Loop accesses `temp[0..n/2]`: with n ≤ 1024, max index is 512, which fits within temp[513]
- All callers (`aactab.c`, `ac3dec.c`, `aacdec_fixed.c`, `aacdec_float.c`, `dolby_e.c`, `ac3enc_float.c`, `ac3enc_fixed.c`) pass **compile-time constants** (128, 256, 960, 1024, etc.) — no user-controlled data reaches `n`
- The function is `av_cold` (init-time only), not on the decoding hot path

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
