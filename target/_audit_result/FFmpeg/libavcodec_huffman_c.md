After thorough multi-pass analysis of `huffman.c` and all its callers, here are the findings:

**Scope covered:**
- Full read of `huffman.c` (202 lines)
- Header `huffman.h`
- All four callers: `fraps.c`, `vp6.c`, `huffyuvenc.c`, `utvideoenc.c`
- Key constants: `VP6_MAX_HUFF_SIZE=12`, `MAX_VLC_N=16384`
- Allocation math for `av_malloc_array` in `ff_huff_gen_len_table`
- `build_huff_tree`'s fixed stack arrays `lens[256]`/`xlat[256]` vs. `pos` count
- `up[]`/`map[]`/`len[]` sub-array bounds within the heap block
- `nodes[-1]` write when `nb_codes=0` (line 179) — not reachable externally

**Key checks performed:**
1. `ff_huff_build_tree`: `nb_codes` values are **hardcoded** compile-time constants at every call site (9, 12, 256) — no attacker-controlled path.
2. `lens[256]`/`xlat[256]` stack arrays: max leaf count equals exactly `nb_codes`; for fraps the max is exactly 256 (writes indices 0–255), no overflow.
3. `ff_huff_gen_len_table` allocation: `56*stats_size` bytes allocated, only `~28*stats_size` bytes actually accessed — correctly over-allocated on 64-bit.
4. `up[h[0].name]` indexing: name values bounded by `[0, 2*size-2]` ⊂ `[0, 2*stats_size-2]`, within `up`'s allocation.
5. `len[-2]` write when `size=0`: intra-heap OOB byte-write of 0 (harmless, writes into `map[]` padding) — only reachable if all stats are zero with `skip0=1` in utvideoenc, not a viable attack primitive.
6. `h[0].val += min1v` after `INT64_MAX` sentinel: the sentinel is pushed away before addition, no overflow.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
