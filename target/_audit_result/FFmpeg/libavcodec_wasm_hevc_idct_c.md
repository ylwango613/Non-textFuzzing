After thorough multi-pass analysis of all 869 lines — including:

- Tracing all stack buffer accesses in `idct_4x4`/`idct_8x8`/`idct_16x16`/`idct_32x32`
- Verifying `store_to_stack` is only reachable from `tr_32x4` with `offset=2048` (within sp[2432])
- Confirming `scale()` and `1 << (shift-1)` are never called with `shift≤0`
- Confirming the caller's `coeffs` buffer (`edge_emu_buffer`, 11360 bytes) far exceeds the 2048-byte maximum needed by 32×32 IDCT
- Verifying the decoder zeroes the full coefficient buffer before IDCT (line 1275 of cabac.c), so the unused `col_limit` causes no memory safety issue
- Confirming all `wasm_v128_load`/`store` accesses stay within their respective stack and heap bounds at all loop iterations (i=0..7 for 32×32, i=0..3 for 16×16)

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
