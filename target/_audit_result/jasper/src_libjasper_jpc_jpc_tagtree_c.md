I now have a complete picture. Let me summarize the findings before giving the final report:

**Analysis summary:**

In `jpc_tagtree_create` (jpc_tagtree.c:95-166), the accumulation `tree->numnodes_ += n` where `n = nplh[numlvls] * nplv[numlvls]` uses signed `int` arithmetic with no overflow guard. For large enough numleafsh × numleafsv this would overflow and cause under-allocation. However:

- `parwidthval` / `parheightval` (precinct sizes) are read from the file with a 4-bit mask (`tmp & 0xf`, jpc_cs.c:808), capping `prcwidthexpn` ≤ 15.
- `cbgwidthexpn` ≤ `prcwidthexpn` ≤ 15, so the precinct's code-block-group width ≤ 2^15 = 32768 pixels.
- `rlvl->cblkwidthexpn = JAS_MIN(ccp->cblkwidthexpn, cbgwidthexpn)`, minimum 2 (since `JPC_COX_GETCBLKSIZEEXPN(x) = x + 2` and `cblkwidthval` is a uint8 starting at 0).
- Therefore `numhcblks = (brcblkxend - tlcblkxstart) >> cblkwidthexpn ≤ 32768 >> 2 = 8192`.
- `numnodes_` maximum ≈ 8192² × 4/3 ≈ 89,478,485 — well within `int` range, no overflow.

The `stk[JPC_TAGTREE_MAXDEPTH - 1]` (= stk[31]) arrays in `jpc_tagtree_encode`/`jpc_tagtree_decode` are also safe: for numhcblks ≤ 8192, numlvls ≤ 14, so at most 13 elements are pushed (well within 31).

`jpc_tagtree_getleaf` has no bounds check, but its callers always use indices 0..(numcblks-1), and numcblks = numnodes_leaves ≤ numnodes_, so no OOB.

The latent integer-overflow bugs exist in the code but are not reachable from a crafted JPEG-2000 file processed by imginfo due to the 4-bit masking of precinct-size fields in the codec stream parser.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
