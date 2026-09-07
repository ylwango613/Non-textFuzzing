Having read the complete 923-line file in two batches and gathered all necessary context, I'll now summarize my analysis:

**Analysis of each major functional area:**

**Batch 1 (lines 1–600):**
- `jpc_dec_decodecblk` (lines 191–336): flags matrix created as `(data.numrows+2) × (data.numcols+2)`. Null return from `jas_matrix_create` properly handled. `bpno` bounded to ≤ 30 because `band->roishift + band->numbps` is clamped to `JPC_PREC−1 = 31` in `jpc_dec.c` line 825. Therefore `one = 1 << bpno` never reaches `1<<31` (no UB).
- `dec_sigpass` / `dec_rawsigpass` (lines 362–551): `fstripestart` starts at `flags[1][1]`; `JPC_UPDATEFLAGS4` accesses `fp[−1..+1]` and `(fp±rowstep)[−1..+1]`. At the minimum (row=1,col=1) and maximum (row=height,col=width) positions, all accesses stay within `flags[0..height+1][0..width+1]` — safely within the allocated (height+2)×(width+2) matrix.

**Batch 2 (lines 600–923):**
- `dec_refpass` / `dec_rawrefpass` (lines 570–748): same flags-matrix boundary analysis; `poshalf`/`neghalf` arithmetic on coefficients is pure value arithmetic, not pointer arithmetic.
- `dec_clnpass` (lines 776–922): `runlen` is decoded from exactly 2 MQ bits (`v` is always 0 or 1 per `jpc_mqstates` table), giving `runlen ∈ {0,1,2,3}`. The switch statement covers all four cases. The `goto clnpass_partial{N}` pattern jumps into macro-expanded labels; `f` and `fp` are set before the jump, no uninitialized-variable UB. The aggregation path's 4-row read is guarded by `vscanlen >= 4`. The `*(fp) &= ~JPC_VISIT` at macro end uses the pre-set `fp`.

**Key safety checks confirmed:**
- `jas_matrix_create` rejects negative dimensions.
- `jas_safe_size_mul` prevents overflow in allocation size.
- JPEG-2000 code-block exponent is capped such that `bpno ≤ 30`.
- `jpc_bitstream_getbit` EOF returns −1; all raw pass steps check `if (v < 0) return -1`.
- Stripe loop (`i += 4` / `i -= 4`) terminates before advancing pointers out of range.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
