Reading the file in passes — starting with lines 0–600, then 600–773. I'll also trace related headers and call paths.

Pass 1 complete (lines 0–600), now I'll analyze key functions before reading the rest.

**Group 1 findings (lines 0–343): Video decoder trees**

- `smacker_decode_tree` (L110): recursion depth guarded by `SMKTREE_DECODE_MAX_RECURSION`; `hc->entries[256]` write guarded by `hc->current >= 256` check. Clean.
- `smacker_decode_bigtree` (L141): `ctx->current >= ctx->length` checked at entry before every write. Node slot pre-allocated with `t = ctx->current++` before recursion; after both children return, `values[t] = SMK_NODE | r`. Clean.
- `smacker_decode_header_tree` (L197): `size >= UINT_MAX>>4` overflow guard; allocates `ctx.length + 3` elements. Post-bigtree `last[0/1/2]` assignments at lines 260–262 write indices up to `ctx.length + 2`, all within the `ctx.length + 3` allocation. Clean.
- `decode_header_trees` (L273): `extradata_size <= 16` guard before the four 4-byte reads; `init_get_bits8` with `extradata_size - 16`. Clean.
- `last_reset` + `smk_get_code`: `last[i]` indices bounded ≤ `ctx.length + 2`; array has `ctx.length + 3` slots. Clean.
- `decode_frame` (L372): pixel writes use `blk < blocks` bound; if `bw == 0` then `blocks == 0` and loop never executes. Clean.

**Group 2 findings (lines 600–773): Audio decoder**

- `unp_size = AV_RL32(buf)` (int, L611): negative values become large unsigned when compared against `(1U<<24)` → caught. Clean.
- `nb_samples = unp_size / (ch * (bits+1))` (L638): divisor is 1/2/4 (ch ∈ {1,2} verified in init, bits ∈ {0,1}); divisibility checked at L639. Clean.
- 16-bit path: after `unp_size /= 2`, total `int16_t` writes = `unp_size` (original/2); allocated capacity = `nb_samples × ch` = original/2. Exact match for all (mono/stereo) subcases, verified algebraically. Clean.
- 8-bit path: total byte writes = `unp_size`; allocated capacity = `nb_samples × ch` = `unp_size`. Clean.
- `vlc[4]` array, `values[4]` array: loop bound is `1 << (bits+stereo) ≤ 4`; idx arithmetic stays within [0,3]. Clean.
- `i += 2` stereo VLC-less loop: `unp_size` is always even (divisibility by 4 enforced for stereo 16-bit), preventing overshoot. Clean.
- Channels mismatch and format mismatch guards at L628/L632 prevent layout confusion. Clean.

**Grep checks performed** (no additional issues found):

- `av_malloc`/`av_malloc_array` calls all have NULL checks and reasonable size guards.
- No `memcpy` with unchecked sizes in this file.
- `smk->mmap_last[i]` indices are always set to valid values before any `smk_get_code` call.
- `FF_CODEC_CAP_INIT_CLEANUP` ensures `decode_end` is called on init failure; all pointers start zero-initialized, making `av_freep(NULL)` safe.

After exhaustive line-by-line analysis of all 773 lines and all reachable code paths, no triggerable memory safety vulnerability was found.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
