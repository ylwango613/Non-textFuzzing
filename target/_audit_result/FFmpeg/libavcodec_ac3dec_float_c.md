Completing the deep analysis of remaining areas before issuing the final report.

**Constants confirmed:**
- `AC3_MAX_COEFS = 256`, `AC3_MAX_CPL_BANDS = 18`, `AC3_MAX_CHANNELS = 7`, `EAC3_MAX_CHANNELS = 16`, `AC3_MAX_BLOCKS = 6`, `SPX_MAX_BANDS = 17`

**Findings per subsystem:**

**`decode_exponents()` — `dexp[256]` and `dexps[]` writes:** `ngrps * 3` ≤ 252 for all channel types; writes land within `int dexp[256]`. `dexps` pointer offset + max `j` (ngrps×3×group_size) stays ≤ 253 for every channel path. Clean.

**`decode_band_structure()` — `bnd_sz[22]` and `band_sizes` memcpy:** Max `n_subbands` = 18 (coupling), max `bnd` = 17 → `bnd_sz[17]`. Final `memcpy(band_sizes, bnd_sz, n_bands)` copies ≤ 18 bytes into destinations of 18 (CPL) / 17 (SPX) bytes. Clean.

**`ff_eac3_apply_spectral_extension()` — `copy_sizes[SPX_MAX_BANDS]` and `num_copy_sections`:** Total wraps bounded by `ceil((spx_dst_end_freq − spx_src_start_freq) / (spx_src_start_freq − spx_dst_start_freq))`. Worst case: distance=12 bins, extension=180 bins → 15 wraps + 1 final = 16 total entries. `copy_sizes` has 17 slots. Clean. SPX `transform_coeffs` write range max end = `spx_dst_end_freq` ≤ 229 < 256. Clean.

**`gaq_gain[AC3_MAX_COEFS]` in `ff_eac3_decode_transform_coeffs_aht_ch()`:** First loop writes at most `ceil(N/3)×3 ≤ 255` entries. Second loop reads exactly `N ≤ 253` entries. All within `gaq_gain[256]`. Clean.

**`ac3_decode_frame()` — `output_buffer[EAC3_MAX_CHANNELS][…]`:** For independent frames: `map = ch < nb_channels ≤ 16`. For dependent frames: `map = 7 + channel_map[x]`, where `channel_map[x] ≤ 5`, giving `map ≤ 12 < 16`. Clean.

**`extended_channel_map[16]` indexing:** `av_channel_layout_index_from_channel()` returns index within `ch_layout.nb_channels`, which is checked ≤ 16 at line 1687. Clean.

**`set_downmix_coeffs()` stack arrays:** `downmix_coeffs[2][AC3_MAX_CHANNELS]`. All writes via `nf = channel_mode − 2` or `− 4` produce indices ≤ 4 for valid modes with `fbw_channels` ≤ 5. Clean.

**`spx_atten_code[ch]` → `ff_eac3_spx_atten_tab[]`:** Value is `int8_t` from `get_bits(gbc,5)` = 0–31; guarded by `>= 0` check; E-AC-3 spec table is correctly sized for 32 entries. Clean.

**`decode_audio_block()` remaining paths:** `start_freq`/`end_freq` derived from validated fields, never exceed `AC3_MAX_COEFS=256`; `coeffs[ch][end]` zeroing loop stops at 255. Clean.

After exhaustive analysis of all array access patterns, integer arithmetic, allocation sizes, and data-flow from the bitstream through every decode path in `ac3dec_float.c` (and the included `ac3dec.c`, `eac3dec.c`), no exploitable memory-safety vulnerability was found.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
