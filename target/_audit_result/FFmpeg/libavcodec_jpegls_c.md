With all bounds confirmed — `s->bits` validated to 1–16, `Ss`/near read as a single byte (0–255), `maxval` as uint16 (0–65535), and no memory allocations in this file — I have completed a full analysis of `jpegls.c` and its call chain.

**Summary of findings:**

- `ff_jpegls_init_state` (lines 34–56): all arithmetic is bounded — `twonear` max 511, `range` max 65536, `qbpp` loop exits by iteration 16 (`1<<16` = 65536 ≥ range), `limit` max ~64, array loops stay within `A[367]`/`N[367]` bounds.
- `ff_jpegls_reset_coding_parameters` (lines 69–108): `maxval` is set to `(1<<bpp)-1` if zero (bpp ≥ 2), so division-by-zero in `256/(maxval+1)` is impossible; T1/T2/T3 clipping via `iso_clip` is safe.
- No heap allocations, no pointer arithmetic, no buffer accesses beyond fixed-size struct fields.
- Callers validate `bits ∈ [1,16]`, `near ∈ [0,255]`, `maxval < (1<<bpp)`, `T1 ≤ T2 ≤ T3 ≤ maxval` before reaching any state-using decode path.
- Array index `Q` in `ff_jpegls_update_state_regular` stays in [0,364]; `C[365]` is never overrun. Runterm path uses Q=365/366 accessing only `A[367]`/`N[367]`/`B[367]`, not `C[365]`.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
