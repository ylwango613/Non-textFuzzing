The `edge_emu_buffer` is allocated as `alloc_size * EMU_EDGE_HEIGHT` where `EMU_EDGE_HEIGHT = 280` rows and `alloc_size = FFALIGN(linesize + 64, 32)`. The worst-case AltiVec `vec_ld(stride + 16, src)` in the last loop iteration accesses at most `src + 16*stride + 31`, far within a 280-row buffer with each row padded to `linesize + 64+` bytes. No OOB access is possible.

After complete analysis of `gmc1_altivec`:
- **Alignment handling**: `vec_ld`/`vec_st` with `dst_odd` and `src_really_odd` correctly covers both aligned and unaligned cases; the merged-store pattern preserves neighboring bytes properly.
- **ABCD computation**: `(16-x16)*(16-y16)` etc., with x16/y16 clamped to `motion_x & 15` ∈ [0,15], max 256 — fits in `unsigned short`.
- **`vec_mladd` chain arithmetic**: cumulative sum bounded by `255 * (A+B+C+D) + rounder = 255*256 + 128 = 65408 ≤ 65535`; no `unsigned short` overflow.
- **Buffer bounds**: `edge_emu_buffer` is 280 rows × (stride+64) bytes, easily covering all 17-row accesses needed, plus the AltiVec over-read of up to 31 extra bytes.
- **Parameters `h`, `x16`, `y16`, `rounder`**: all constrained by the caller (`h` ∈ {8,16}, x16/y16 ∈ [0,15], rounder ∈ {127,128}); no attacker-controlled unbounded value reaches the function.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
