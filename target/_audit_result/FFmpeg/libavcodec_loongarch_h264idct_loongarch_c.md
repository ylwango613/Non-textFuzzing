After fully reading the 185-line file and tracing all relevant context:

**Key findings from analysis:**

1. `scan8[]` is `uint8_t[51]`. Max index accessed: `scan8[43]` (in `ff_h264_idct_add8_422_8_lsx`, loop `i=36..39`, `scan8[i+4]`). Array size 51, index 43 — in bounds.

2. `nzc[]` is `uint8_t[120]`. Values from `scan8[40..43]` = {108, 109, 116, 117}, all < 120 — in bounds.

3. `blk_offset[]` max index is 43 (`blk_offset[i+4]` with `i=39`). The caller allocates `h->block_offset[96]` and passes pointer at offset 0 or 48 — max access `blk_offset[43]` = `h->block_offset[43]` or `h->block_offset[91]`, both < 96 — in bounds.

4. `block + i * 16 * sizeof(pixel)` — at 8-bit depth (`sizeof(pixel)=1`), max index `39*16=624`; `sl->mb` is `int16_t[1536]` — in bounds.

5. `((dctcoef *) block)[i * 16]` — same bounds, in bounds.

6. All loop bounds match the reference implementation in `h264idct_template.c`. No divergence found.

No externally-controllable index, no unsafe allocation size, no out-of-bounds access path.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
