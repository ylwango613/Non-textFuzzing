**Complete analysis:**

1. **All buffer sizes are compile-time constants**: `buf[NELLY_FILL_LEN=124]`, `pows[NELLY_FILL_LEN=124]`, `bits[NELLY_BUF_LEN=128]`, `imdct_buf[2][128]` — no external data controls any size.

2. **Band iteration**: `ff_nelly_band_sizes_table` is a static array summing to exactly 124 = NELLY_FILL_LEN (verified: 2×9+3×2+4×2+5+6×2+7+8+9+10+12+14+15 = 124), so the `bptr`/`pptr` increments in `nelly_decode_block` always stay within `buf[]`/`pows[]` bounds.

3. **Dequantization table indexing** at line 104: `bits[j]` is clipped to [0, NELLY_BIT_CAP=6] by `ff_nelly_get_sample_bits`. For bits[j]=6 (maximum), `(1<<6)-1 + v = 63 + v` where v ∈ [0,63], giving maximum index 126. The table has exactly 127 entries (indices 0–126) ✓.

4. **Bit budget arithmetic**: NELLY_BLOCK_LEN×8 = 512 bits; NELLY_HEADER_BITS(116) + 2×NELLY_DETAIL_BITS(198) = 512. `ff_nelly_get_sample_bits` enforces sum(bits) ≤ NELLY_DETAIL_BITS = 198, so `get_bits` reads in the second pass never exceed the block boundary.

5. **`decode_tag` overflow check** at line 159: the guard `blocks > INT_MAX / NELLY_SAMPLES` correctly prevents `frame->nb_samples = NELLY_SAMPLES * blocks` from overflowing.

6. **No heap allocations with attacker-controlled sizes** — no `av_malloc`/`av_realloc`/`memcpy` calls exist in this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
