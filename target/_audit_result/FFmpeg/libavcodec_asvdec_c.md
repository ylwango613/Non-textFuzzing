I've now done a complete analysis of `asvdec.c` and all relevant context:

**Analysis summary:**

1. **`asv2_decode_block` `count` field (lines 161, 175-188):** `count = get_bits_le(&a->gb, 4)` gives 0–15. Loop `for (i = 1; i < count+1; i++)` → max `i=15`. Maximum array index: `4*15+3 = 63`. Both `permutated_scantable[64]` and `intra_matrix[64]` have exactly 64 elements. On-boundary, not over.

2. **`block[permutated_scantable[...]]` write:** `ff_permute_scantable` guarantees output values are in [0,63] for all permutation types (confirmed by reading `idctdsp.c:30-37`). `ff_asv_scantab` values are all ≤ 0x3F. Block is `int16_t[64]`. No OOB.

3. **`asv1_decode_block` (lines 126-155):** Explicit guard `if (ccp < 0 || i >= 10)` returns `AVERROR_INVALIDDATA` before any array access when `i = 10`. Max working access is `4*9+3 = 39`. Safe.

4. **`av_fast_padded_malloc` in `decode_frame` (line 249):** Allocates `buf_size + AV_INPUT_BUFFER_PADDING_SIZE`. `bswap_buf` copies `buf_size/4` uint32s — never more bytes than allocated. Safe.

5. **`decode_init` extradata access (line 316):** Guarded by `avctx->extradata_size < 1` check. Safe.

6. **`intra_matrix` init (line 327):** `ff_asv_scantab[i]` ∈ [0,63] → `ff_mpeg1_default_intra_matrix[index]` (256 elements) is always in bounds.

7. **`idct_put` frame pointer arithmetic:** Bounded by `mb_height`/`mb_width` from `ff_asv_common_init`, which derives from `avctx->height`/`width`. No integer overflow at practical FFmpeg dimension limits.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
