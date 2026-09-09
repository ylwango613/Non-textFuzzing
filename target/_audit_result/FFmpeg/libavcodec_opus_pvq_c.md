Now I have the complete picture. Let me verify the final key bounds:

- `ff_celt_pvq_u_row[15]`: 15 rows (indices 0–14). Row index in `celt_cwrsi` is `N` (lots-of-pulses branch, K≥N) or `K` (lots-of-dimensions branch, K<N). Safety invariant required: min(N,K) ≤ 14.
- `celt_pvq_u[1272]`: column accesses with col = up to 176 stay within the flat array (row boundaries are aliased but not past 1272). No hard OOB crash.
- `qcoeff[256]` and `hadamard_tmp[256]`: N ≤ 176 (max band with size=3) < 256. Safe.
- Cache index 92 (band 8, duration=3) = **305** → `ff_celt_cache_bits[305]`. The value there bounds q_max. The CELT range-coder precision (uint32_t) mathematically caps K such that min(N,K) ≤ 14 for all conforming and attacker-crafted streams — V(N,K) overflows uint32_t before K can reach 15 when N > 14.
- `celt_exp_rotation_impl`: `len - 2*stride - 1` uint32_t underflow is possible but the loop bound is assigned to signed `int i` which becomes negative → loop body never executes → no OOB dereference.
- `celt_interleave_hadamard` / `celt_deinterleave_hadamard`: `hadamard = longblocks = (B0 == 1)`, so stride in hadamard mode = `1 << recombine` ≤ 8 → table offset stride-2 ≤ 6, within the 30-element ff_celt_hadamard_order table.
- No heap allocations (except the single correct `av_malloc(sizeof(CeltPVQ))` in `ff_celt_pvq_init`).

After reading the entire 931-line file in full and tracing all allocation, array-index, and loop-bound paths with supporting context from pvq.h, celt.h, and tab.c:

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
