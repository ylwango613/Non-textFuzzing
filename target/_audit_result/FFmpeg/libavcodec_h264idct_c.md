After thorough analysis of `h264idct.c` (which includes `h264idct_template.c`), I have verified:

1. **All `block` array accesses** — `block + i*16*sizeof(pixel)` in `add16`, `add16intra`, `add8`, `add8_422`, `add8x4` — stay well within `sl->mb[1536]` bounds across all BIT_DEPTH instantiations (8/9/10/12/14).

2. **`scan8[]` indexing** — max access is `scan8[43]` (in `add8_422` second loop), value 117; array has 51 entries, values reach max 117 < 120 (nnzc declared `[15*8]`). No OOB.

3. **`block_offset[]` accesses** — `h->block_offset[2*(16*3)]` = 96 entries; max index used is `block_offset[43]` from frame base or `block_offset[43]` from field base (`&h->block_offset[48]` → `h->block_offset[91]`). All within bounds.

4. **`luma_dc_dequant_idct` output** — max index `stride*5 + x_offset[3]` = `80 + 160 = 240` dctcoef elements; even for p=2, 16-bit depth, stays within `sl->mb` 3072-byte limit.

5. **`chroma422_dc_dequant_idct` block** — max access `block[stride*3 + xStride*1]` = `block[112]`; fits within the chroma region of `sl->mb`.

6. **No dynamic allocations** (`av_malloc`/`av_realloc`) anywhere in the file; all data structures are fixed-size statically-bounded arrays.

7. **`dest[j-1]` pointer** — `dest` is `uint8_t *[2]` at the call site; `j=1,2` accesses `dest[0]` and `dest[1]` only. No OOB.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
