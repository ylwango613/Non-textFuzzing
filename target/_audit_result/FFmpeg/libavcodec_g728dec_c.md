I have now completed a thorough, multi-pass analysis of `g728dec.c` and its full call chain.

**Analysis summary:**

1. **Integer overflow candidate (`nb_frames * SAMPLES_PER_FRAME`, line 197):** `avpkt->size / 5 * 20` could theoretically overflow a 32-bit int if `avpkt->size > 536,870,910`. However, `init_get_bits8()` at line 192 guards this path: it rejects any `byte_size > INT_MAX/8 = 268,435,455`, returning `AVERROR_INVALIDDATA` before execution reaches line 197. For all values of `avpkt->size` that pass this check, `nb_frames ≤ 53,687,091` and `nb_frames * 20 ≤ 1,073,741,820 < INT_MAX` — no overflow is possible.

2. **`vector_fmul` reads slightly past `s->sbg`/`s->sb` in `do_hybrid_window`:** The call length `FFALIGN(order+n+non_rec, 16)` is rounded up to a SIMD-multiple (48 or 112 elements), while `sbg` holds only 34 and `sb` holds only 105 elements. The extra 14 / 7 reads land in adjacent struct fields (`gp`/`sbg`) within the same contiguous heap allocation — this is a correctness bug (wrong data used in computation) but not a memory-safety violation.

3. **All `codetable[is]`, `amptable[ig]` accesses:** Indexes are 7-bit (`is` 0–127) and 3-bit (`ig` 0–7), matching the declared table dimensions exactly. No OOB.

4. **All `memmove`, struct-field writes, `ff_celp_lp_synthesis_filterf` history reads:** Verified in bounds for all loop iterations.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
