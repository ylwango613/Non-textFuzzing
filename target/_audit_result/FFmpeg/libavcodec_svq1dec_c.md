After completing full analysis of all 874 lines of `svq1dec.c` in multiple batches, along with the codebook definitions in `svq1_cb.h` and struct declarations in `svq1.h`, here is my finding summary:

**Key areas checked:**

1. **`list[63]` array bounds in `svq1_decode_block_intra/non_intra`**: The SVQ1_PROCESS_VECTOR macro can add at most 62 children (binary tree, levels 5→0). `n` starts at 1, increments by 2 each time → n ∈ {1,3,5,...,63}. Maximum writes are to `list[61]` and `list[62]`, both valid (63-element array, indices 0..62). ✓

2. **Codebook OOB via `codebook[entries[j]] + codebook++`**: For each level (0–3, where `stages>0` is permitted), the formula `entries[j] = (nibble + 16*j) << (level+1)` + the advancing-pointer pattern gives a maximum index of exactly `codebook_size - 1`: level-0: 191 < 192; level-1: 383 < 384; level-2: 767 < 768; level-3: 1535 < 1536. ✓

3. **NULL codebooks at levels 4/5**: `ff_svq1_inter_codebooks[4]` and `[5]` are NULL, but the check `if (stages > 0 && level >= 4) return error` always fires before `SVQ1_CALC_CODEBOOK_ENTRIES` can dereference them. ✓

4. **`svq1_parse_string` stack buffer**: `out[257]` accommodates max write at `out[256]` (when `out[0]=255`). ✓

5. **Header swap**: `buf_size < 9*4=36` is checked before accessing `src[7]` at byte 32. ✓

6. **PMV array**: Allocated for `(FFALIGN(s->width,16)/8 + 3)` elements; maximum index accessed for both luma (`x/8+4`) and chroma planes is always within bounds. ✓

7. **Width/height from bitstream**: 12-bit max (4095); no integer overflows in subsequent FFALIGN arithmetic (max product 4096×4096 = 16M, within 32-bit int). ✓

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
