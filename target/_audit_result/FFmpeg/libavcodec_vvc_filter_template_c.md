After a full multi-pass review of the file and its complete calling context, here is what I verified:

**Pass 1 (lines 1–135): `lmcs_filter_luma`, `alf_filter_luma`**
- `lut[dst[x]]`: lut is `u8[4096]`/`u16[4096]` (`LMCS_MAX_LUT_SIZE=4096`), bit depth validated to ≤12 (`LMCS_MAX_BIT_DEPTH`), so pixel values ≤ 4095 are always within bounds.
- Filter/clip pointers advance by `ALF_NUM_COEFF_LUMA=12` per x-block; total writes match `coeff_tmp[ALF_MAX_FILTER_SIZE]` = 12288 exactly.
- p0–p6 pointer substitution near virtual boundaries: correct per VVC spec; does not escape the padded buffer (`ALF_PADDING_SIZE=8` rows covers max 6-row overshoot).

**Pass 2 (lines 136–253): `alf_filter_chroma`, `alf_filter_cc`**
- Chroma filter: same padded-buffer analysis; 4-row maximum vertical overshoot covered by 8-row padding.
- `alf_filter_cc`: `(y<<vs)` row access with `s3 = src + 2*stride` goes at most to luma row 2×chroma_height = luma_height → inside padding.

**Pass 3 (lines 260–398): `alf_get_idx`, `alf_classify`, `alf_recon_coeff_and_clip`**
- `transpose_idx` = `dir_d*2 + dir_hv` ∈ {0,1,2,3}; `index[4][12]` → no OOB.
- `class_idx` max = `arg_var[0..15]` (0–4) + `(1*2+2)*5 = 20` = **24**; `class_to_filt[25]` and `clip_idx_set[25×12]` → indices 0–24 all valid.
- `clip_set[clip_idx[idx]]`: `clip_idx` comes from `alf_luma_clip_idx` which is `ubs(2, ...)` → values 0–3, within `clip_set[4]`.
- `gradient_tmp[66×66×4=17424]`: fill loop max index = 17423 = buffer bound − 1; accumulation loop stays within the same range.

**Included h2656_sao_template.c**: SAO band filter uses `(src[x] >> shift) & 31` → always 0–31, within `offset_table[32]`. Edge filter `edge_idx[2 + diff0 + diff1]`: diff0,diff1 ∈ {-1,0,1} so index ∈ {0,1,2,3,4} → valid for `edge_idx[5]`.

All bounds are tightly enforced by: the 8-row ALF padding, the `CLIP`/`av_clip_pixel` macro on every output, the 2-bit bitstream parsing of clip indices, the LMCS bit-depth guard, and the VVC-spec–fixed class/transpose index ranges.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
