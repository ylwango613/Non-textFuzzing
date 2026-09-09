After an exhaustive multi-batch analysis of the full `vp9recon.c` file and all relevant supporting code, here are my findings:

**Batch 1 (lines 1–300): `check_intra_mode` and `intra_recon`**
- `a_buf[96]` with `a = &a_buf[32]`: max positive write = `n_px_need * bpp - 1 = 32*2-1 = 63` bytes past `a` → `a_buf[95]`. Buffer is 96 bytes [0..95]. ✓
- `(*a)[-1]` (topleft) writes at `a_buf[30..31]`. ✓
- `l[64]`: max write at `l[(n_px_need-1)*2+1] = l[63]`. ✓
- `n_px_have` always ≥ 4 (bounded by loop end_x/end_y from `FFMIN(2*(cols-col), w4)`). ✓
- EOB buffer: `td->eob[n]` max n = 240 with 2-byte AV_RN16A read → `eob[241]`, buffer is 256 bytes. ✓

**Batch 2 (lines 300–414): `mc_luma_unscaled`, `mc_chroma_unscaled`**
- `edge_emu_buffer[135*144*2 = 38880 bytes]`, stride 160, max bh+7 = 71 rows → 160×71 = 11360 bytes. ✓
- U/V emulation sequenced correctly: U fill → U MC call → V fill → V MC call. ✓

**Batch 3 (lines 415–577): `mc_luma_scaled`, `mc_chroma_scaled`**
- `refbh_m1 + 8` ≤ 134 rows with stride 288, buffer = 38880 / 288 = 135 rows. ✓
- `mvstep` bounded by VP9 2× scale limit: step ≤ 32. ✓

**Batch 4 (lines 578–663): `inter_recon`**
- `tx = 4 * lossless + b->tx`: lossless forces `txfmmode = TX_4X4` → b->tx = 0 → tx = 4. `itxfm_add[5]` valid. ✓
- `td->block + 16 * n * bytesperpixel`: for TX_32X32/16bpp, max n=192, offset = 6144 int16_t, buffer = 8192 int16_t. ✓
- UV coefficient accesses similarly bounded. ✓

**Supporting structures verified:**
- `ff_vp9_bwh_tab[1][BS_8x4] = {1,1}`: h4 = 2 (representing full 8×8 superblock container height) is intentional; sub-8x8 blocks fill a full 8×8 container; `b->mode[3]` is always initialized (= `b->mode[2]` for BS_8x4). ✓
- `ff_vp9_scans[5]` and `itxfm_add[N_TXFM_SIZES+1=5]` arrays: tx index 4 (lossless WHT) is valid. ✓
- Mode conversion: `mode_conv[mode][have_left][have_top]` → always maps to valid [0..N_INTRA_PRED_MODES-1]. ✓

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
