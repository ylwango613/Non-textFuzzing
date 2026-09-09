Based on my exhaustive multi-pass analysis of all 1328 lines of `dec.c`, plus investigation of related headers (`dec.h`, `ps.h`, `ctu.h`), `ps.c`, `filter.c`, and `ctu.c`, here are my key findings:

**Batch 1 (lines 1–400):** Analyzed all `tl_init_fn` functions. The `TL_ADD(coeffs, ctu_count * ctu_size * VVC_MAX_SAMPLE_ARRAYS)` expression (line 126) performs signed-int multiplication that can overflow when `ctu_count × ctu_size × 3 > INT_MAX`. Analysis shows: at the maximum reachable dimensions for any valid `ctb_log2_size_y` (5–7, validated in ps.c:765), the product is exactly `3 × 2^32 ≡ 0 (mod 2^32)`, so `av_malloc(0)` returns NULL → ENOMEM (DoS, not underallocation). Sub-max values yield a negative int → huge `size_t` → malloc fails. No heap underallocation path exists.

**Batch 2 (lines 401–700):** Analyzed `pic_arrays_init`, `slices_realloc`, `get_ep_size`, `ep_init_cabac_decoder`, `slice_init_entry_points`. All size/index computations are bounded by validated parameters. `pic_size_in_min_pu = min_pu_width × min_pu_height` max is `16383² ≈ 268M`, safe for int32. `nb_eps = num_entry_points + 1` is capped at `VVC_MAX_ENTRY_POINTS = 4050 + 1`. CTB raster addresses indexing `fc->tab.slice_idx[rs]` are computed from tile structure, bounded by `ctb_count`.

**Batch 3 (lines 700–1328):** Analyzed frame setup/teardown, film grain, hash check, frame submission. No unsafe memory operations identified.

**Cross-validation (ctu.c:2816):** The indexing `fc->tab.coeffs + rs * ctb_size * VVC_MAX_SAMPLE_ARRAYS` holds a safety invariant: if the `coeffs` buffer allocation succeeded, `ctu_count × ctu_size × 3 ≤ INT_MAX`, meaning `rs < ctu_count` guarantees `rs × ctu_size × 3 < INT_MAX` — no overflow in pointer arithmetic.

**CBS parser bounds:** `ctb_log2_size_y ∈ {5,6,7}`, `pps->width/height ≤ 65535` (uint16_t), conformance window offsets validated, `num_entry_points ≤ 4050`.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
