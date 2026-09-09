After a thorough multi-pass audit of `twinvqdec.c` (427 lines, fully read) and the complete shared implementation `twinvq.c` (803 lines, fully read), plus all referenced headers, I analyzed every relevant code path:

**Group 1 – Init / extradata parsing (twinvqdec.c:318-413)**
- `channels = AV_RB32(extradata) + 1`: uint32 wrap to 0 or signed overflow to negative both caught by `channels <= 0` guard (line 350). ✓
- `bit_rate = AV_RB32(extradata+4) * 1000`: 32-bit multiply may wrap but the resulting garbage is caught by `ibps < 8 || ibps > 48` check (line 359). ✓
- `frame_size = bit_rate * mtab->size / sample_rate + 8`: bit_rate is constrained by ibps check; max ≈ 96000; `96000 * 2048 / 8000` ≈ 24576 – no overflow. ✓

**Group 2 – Buffer allocations (twinvq.c:553-574)**
- `table_size = 2 * channels * mtab->size` ≤ 2·2·2048 = 8192; no overflow, all `FF_ALLOC_TYPED_ARRAY` calls use this. ✓
- `cos_tabs[i]` allocated with `m/4` elements; write loops stay ≤ `m/4-1`. ✓

**Group 3 – Permutation tables (twinvq.c:583-668)**
- `permutate_in_line` write guard `j + num_vect * i < block_size * num_blocks = vect_size` ensures writes into `tmp_perm` stay within `vect_size ≤ 2*mtab->size` elements (tmp_buf has `mtab->size * sizeof(float)/sizeof(int16_t) = 2*mtab->size` int16_t elements). ✓
- `transpose_perm` read access maximum index proven to be `vect_size - 1`. ✓
- `permut[ftype]` is `[4][4096]`; all values and indices ≤ vect_size ≤ 4096. ✓

**Group 4 – Bitstream reads (twinvqdec.c:250-316)**
- `bark1[channels][sub][coef]` ≤ `[2][16][4]`; all loops bounded by TWINVQ_*_MAX constants that match array dimensions exactly. ✓
- `sub_gain_bits[channels * sub]` max index = 1·16+15 = 31 < 32. ✓
- `read_cb_data` writes `2 * n_div[ftype]` bytes; for main_coeffs (1024 bytes) n_div ≤ 319 → 638 bytes; for ppc_coeffs (60 bytes) n_div[3] ≤ 2 → 4 bytes. ✓

**Group 5 – add_peak / very_broken_op (twinvqdec.c:132-175)**
- Maximum speech buffer access ≈ `ppc_shape_len * mtab->size / peak_per2wid`: for all modes this is well below `mtab->size` (e.g., mode_08_08: 20·512/40=256 < 512; mode_44_40: 40·2048/432≈190 < 2048). ✓
- `tabs[b/5]` with b ∈ [1,59] divisible by 5: b/5 ∈ [1,11], within `tabs` array of 13 entries. ✓
- `a*b+200` max ≈ 30720·59+200 ≈ 1.8M – no int32 overflow. ✓

**Group 6 – LSP / dequant / imdct (twinvq.c)**
- `dequant` permut indices sum to ≤ vect_size ≤ spectrum buffer size. ✓
- `decode_lsp` codebook indices bounded by `get_bits(lsp_bit*)`. ✓
- `imdct_output` memcpy end addresses stay within `prev_frame` / `curr_frame` bounds. ✓

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
