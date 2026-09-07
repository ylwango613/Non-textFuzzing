Based on my complete analysis of `/data/ylwang/non-textfuzz/target/jasper/src/libjasper/base/jas_seq.c` (516 lines, read in full), including all related headers and calling contexts:

**Group 1 (lines 87–209): Constructors/destructors**
- `jas_matrix_create` uses `jas_safe_size_mul` for the `numrows × numcols` product — safe.
- `jas_matrix_destroy`, `jas_seq2d_copy`, `jas_matrix_copy` — straightforward, no OOB risk.

**Group 2 (lines 215–261): Bind operations**
- `jas_matrix_bindsub` computes `r1 - r0 + 1` (could overflow if `r0` large-negative and `r1` large-positive), but this simplifies to `yend - ystart` through `jas_seq2d_bindsub`, and any overflow in `maxrows_` passes a negative value to `jas_alloc2` which would fail → `abort()`, not heap corruption.

**Group 3 (lines 267–405): Arithmetic + resize**
- `jas_matrix_resize` (line 392) uses plain signed `numrows * numcols` with no `jas_safe_size_mul`. On x86-64, `int_fast32_t` = 64-bit `long`. Overflow requires product > 2^63 ≈ 9.2e18. JPEG-2000 SIZ uint32 dimensions cap at 4.3e9; a 4.3e9 × 2.2e9 product would overflow. However: any matrix large enough to hit this path requires a `rows_` allocation of ~34 GB, which fails in `jas_matrix_create` before `jas_matrix_resize` is ever reached. The check `numrows > matrix->maxrows_` blocks mismatched resize attempts. Not practically exploitable.

**Group 4 (lines 428–515): File I/O**
- `jas_seq2d_input` has `xoff + numcols` computed as plain `int_fast32_t` addition (potential signed overflow), but grep confirms this function has **zero callers** in the entire source tree — not reachable from any image decoding path.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
