After exhaustive analysis of all 1555 lines across multiple passes, checking every array index derivation, malloc sizing, integer arithmetic, and all relevant calling context:

- All array accesses (`dist->freq[258]`, `dist->cutoffs[258]`, `dist->symbols[258]`, `dist->offsets[258]`) are bounded by `alphabet_size ≤ table_size ≤ 256`, which is within the 258-element arrays.
- `level2_lens`, `level2_lens_s`, `level2_syms` (each 32768 elements) and `level2_codecounts` (32769 elements) are correctly sized and their indices are bounded by `dist->alphabet_size ≤ MAX_PREFIX_ALPHABET_SIZE = 32768`.
- `cluster_map` allocation matches `num_dist` in all access patterns; `dists[]` access is guarded by `cluster_map[context] >= num_clusters` check.
- `dec->window` accesses are masked with `& 0xFFFFF` (1M element window is correct).
- `overfull[256]` and `underfull[256]` can hold at most `table_size ≤ 256` entries simultaneously, never exceeding bounds.
- The `div_ceil(0, upsampling)` underflow when crop width=0 causes `toc_count` to be very large, creating a CPU-exhaustion DoS, but the checked bitstream reader (`UNCHECKED_BITSTREAM_READER 0`) ensures no memory reads beyond buffer bounds.
- The signed/unsigned comparison in `skip_extensions` (`int < uint64_t`) can bypass an exhaustion check, but subsequent reads are all checked and cannot access out-of-bounds memory.
- All `skip_bits_long` calls are bounded by prior `get_bits_left` checks or hardcoded constants.
- `num_dist` is always passed as small hardcoded constants (1, 8, 41) at all public entry points, preventing any overflow via `num_dist++`.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
