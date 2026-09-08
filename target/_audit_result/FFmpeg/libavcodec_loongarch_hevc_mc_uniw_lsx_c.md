The analysis is complete. This file (`hevc_mc_uniw_lsx.c`) is a pure LoongArch LSX SIMD motion-compensation kernel for HEVC weighted uni-prediction. Key observations:

- **Filter indexing**: `ff_hevc_qpel_filters[mx]` / `ff_hevc_qpel_filters[my]` — both `mx` and `my` are masked to `& 3` at the call site in `hevcdec.c:1733-1734`, always yielding indices 0–3 into the `[4][16]` table. Safe.
- **Source buffer**: Edge emulation is applied before the kernel is called whenever the block is out-of-frame bounds (`luma_mc_uni` lines 1743–1758). The kernel itself performs no bounds checking but doesn't need to.
- **Width parameter**: Comes only from the fixed wrappers (8, 16, 24, 32, 48, 64 — constants, not attacker-controlled at the SIMD level).
- **Height parameter**: `block_h` in HEVC is always a positive even integer ≥ 4 by the standard; the inner `height >> 1` loop is safe.
- **No dynamic allocation**: No `av_malloc`/`memcpy` with attacker-controlled sizes exist in this file.
- **Stride arithmetic**: All stride shifts use `int32_t` on values bounded by practical frame dimensions; no realistic overflow path.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
