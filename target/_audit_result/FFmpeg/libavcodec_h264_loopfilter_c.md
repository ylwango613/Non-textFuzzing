Based on my thorough analysis of all 847 lines of `h264_loopfilter.c` plus the relevant context from headers and calling code, here is what I found:

**Batch 1 (lines 1-413):** Table lookups using `index_a = qp + a` and `qp + b` into `alpha_table[52*3]`, `beta_table[52*3]`, `tc0_table[52*3][4]`. Potential OOB concern analyzed.

**Batch 2 (lines 414-847):** MBAFF special-case handling, `filter_mb_dir`, `ff_h264_filter_mb`.

**Analysis of `index_a` bounds:**
- `qp` from `qscale_table` (int8_t) is validated at parse time to `[0, 51+6*(bit_depth-8)]` (h264_cavlc.c:1093-1107, h264_slice.c:1887-1890)
- `slice_alpha_c0_offset_div2` validated to `[-6,6]` → offset in `[-12,12]`
- Max `index_a = 51 + 52 + 12 = 115` — within table bound of 155. Safe.

**Analysis of `tc0_table[index_a][bS[i]]` second index:**
- When `intra=1` and `bS[0]>=4` → else branch (no tc0_table access). Safe.
- When `intra=0` → always tc path, but bS values for interior edges are 0/1/2 from NZC or MV checks, or 3 for intra MBs — all within `[0,3]`. Safe.
- MBAFF bS arrays: the per-macroblock filling ensures that within each individual filter call, all sampled elements come from the same neighboring macroblock, so they are uniformly intra (→ else path) or uniformly non-intra (→ valid index ≤ 2). Safe.

**Cache array bounds** (`ref_cache[2][5*8]`, `mv_cache[2][5*8][2]`, `non_zero_count_cache[15*8]`):
- All `b_idx`/`bn_idx` values: max 39, within `[0,39]`. Safe.

**Pixel pointer arithmetic:** All frame buffer offsets are bounded by macroblock dimensions (16×16 luma, 8×8 chroma) which are consistent with the allocated frame buffer size.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
