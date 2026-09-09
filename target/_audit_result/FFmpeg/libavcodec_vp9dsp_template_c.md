All three critical stack buffer computations are safe under the enforced input constraints:

- `vp9.c:867` rejects any reference frame where `refw > 2*w`, guaranteeing `mvstep ≤ 32`
- `do_scaled_8tap_c`: tmp_h = 134 ≤ array size 135 rows (exact fit)
- `do_scaled_bilin_c`: tmp_h = 128 ≤ array size 129 rows (exact fit)  
- `do_8tap_2d_c`: tmp_h = 71 = array size 71 rows (exact fit)

All intra prediction arrays (`v[size-1]`, `v[size+size-1]`, `v[size*3-2]`, etc.), loop filter accesses, IDCT arithmetic, and MC filter buffers were traced through their full boundary conditions. The file uses only stack and caller-allocated buffers; no heap allocation, no external data directly driving unchecked array indexing. The VP9 decoder infrastructure provides the required horizontal/vertical source padding before any of these DSP functions are called.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
