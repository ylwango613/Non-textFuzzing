All key constants are now confirmed: `SBLIMIT=32`, `MPA_MAX_CHANNELS=2`, `mpc_CC` has 19 entries, `mpc_SCF` has 256 entries, and `mpc8_bands_syms` max symbol is 32.

Let me verify the critical bounds exhaustively:

**`c->Q[ch][off + j]` (line 306, 315, etc.):** `off` = `i * 36`, with `i` up to `maxband-1` ≤ 31 → max offset = `31*36+35 = 1151 = MPC_FRAME_SIZE-1`. Within `Q[2][1152]`. ✓

**`bands[i]` (line 234):** `i` ≤ `maxband-1` ≤ 31. Within `Band bands[32]`. ✓

**`mpc8_cnk_len[k-1][n-1]` / `mpc8_cnk[k-1]` (lines 46, 58):** Called from `mpc8_get_mod_golomb` (k=1 always) and `mpc8_dec_enum` with k=FFMIN(t, cnt-t) ≥ 1 (because t>0 and t<cnt). n≤32, k≤16, tables are [16][33] and [16][32]. ✓

**`(mpc_CC+1)[res]` (mpc.c:70):** `res` ∈ [-1,15] → indices mpc_CC[0..16], within 19-element array. ✓

**`mpc_SCF[scf_idx & 0xFF]` (mpc.c:70):** `& 0xFF` enforces [0,255], within 256-element `mpc_SCF`. ✓

**`sb_samples[ch][j][i]` (mpc.c:72):** `i` ≤ passed `maxband` = original_maxband-1 ≤ 31 < SBLIMIT=32. ✓

**`scfi_vlc[cnt]` (line 267):** `cnt` = `!!res[0] + !!res[1] - 1` ∈ {0,1}, within `scfi_vlc[2]`. ✓

**`quant_vlc[res-5][cnt > mpc8_thres[res]]` (line 343):** res∈[5,8] → index 0..3 in `quant_vlc[4][2]`. ✓

**`maxband` validation:** Keyframe: bounded by Golomb code semantics to [0, c->maxbands+1]. Non-keyframe: any large VLC sum is caught by `if(maxband > c->maxbands+1)` → AVERROR_INVALIDDATA. ✓

**`init_get_bits(&gb, avctx->extradata, 16)` (line 156):** Extradata checked ≥ 2 bytes = 16 bits; all subsequent reads sum to exactly 16 bits. ✓

After a complete analysis of every array access, pointer arithmetic, and size computation in `mpc8.c` and its direct callees (`mpc.c`), all bounds are enforced. No externally triggerable memory safety vulnerability is present.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
