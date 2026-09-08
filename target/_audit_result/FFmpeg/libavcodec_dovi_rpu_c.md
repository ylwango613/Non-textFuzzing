After reading all code paths in `dowi_rpu.c`, `dowi_rpudec.c`, `dowi_rpuenc.c`, the BSF wrapper, and the relevant headers (`dowi_rpu.h`, `dowi_meta.h`), here is my analysis:

**Pass 1 (dowi_rpu.c):** Only 136 lines of initialization/cleanup. No allocations or pointer arithmetic.

**Pass 2 (dowi_rpudec.c – parse path):**
- `get_variable_bits()` can unsigned-overflow but result is immediately `VALIDATE`d to [6,512]; no memory safety consequence.
- `VALIDATE(num_pivots_minus_2, 0, AV_DOWI_MAX_PIECES - 1)` → `num_pivots` ∈ [2,9]; `pivots[AV_DOWI_MAX_PIECES+1]` has 9 slots; loop safe.
- `poly_coef[i][k]` with `i ≤ 7`, `k ≤ 2`; array is `[8][3]` — safe.
- `mmr_coef[i][j][k]` with `i ≤ 7`, `j ≤ 2`, `k ≤ 6`; array is `[8][3][7]` — safe.
- `parse_ext_blocks`: `num_ext_blocks` from `get_ue_golomb_31` ≤ 31; explicit bounds checks (`num_static >= FF_ARRAY_ELEMS(dm_static)` → error) before every array write.
- Extension blocks: `dm_static[7]` + `dm_dynamic[25]` = 32 total matches `AV_DOWI_MAX_EXT_BLOCKS = 32`; copy loop in `ff_dowi_get_metadata` iterates only up to those counts — no OOB.
- CRC path: `rpu_size - 1` is always ≥ 6 by the time of the check.

**Pass 3 (dowi_rpuenc.c – generate path):**
- `buffer_size` calculation: empirically verified: header ≤ 79 bytes < 160 bytes; polynomial piece ≤ 189 bits < 26 bytes×8=208 bits; MMR piece ≤ 1390 bits < 177 bytes×8=1416 bits. No underallocation.
- Encoder copy loop (lines 948-953): writes at most `num_static ≤ 7` static and `num_dynamic ≤ 25` dynamic entries — exactly the array dimensions.
- `try_reuse_ext`: all accesses within `ext->num_static ≤ 7` and `metadata->num_ext_blocks ≤ 32 = AV_DOWI_MAX_EXT_BLOCKS`.

**BSF wrapper:** Correctly threads parse→metadata→generate; no independent allocations or unsafe copies.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
