I've now read and analyzed all 2171 lines across four passes, plus consulted the header and confirmed there are no `av_malloc`/`memcpy` calls in this file at all.

**Summary of analysis across all code groups:**

**Batch 1 (lines 1–550):** Macro-only section defining VP9 IDCT/ADST primitives using MIPS MSA SIMD intrinsics. All intermediate registers are local SIMD variables. No dynamic allocation.

**Batch 2 (lines 550–1099):** 4×4, 8×8 transform functions. All load/store operations use fixed strides matching the fixed block dimensions (4, 8). No user-controlled sizes used as indices.

**Batch 3 (lines 1100–1649):** 16×16 and start of 32×32 logic. Temporary buffers (`out_arr[16*16]`, `out[16*16]`) are compile-time fixed at exactly 256 `int16_t`s. Function `vp9_idct16_1d_columns_msa` stores to `output` at max offset `output[8 + 4*16 + 7]` = `output[119]` < 256. All accesses proven in-bounds.

**Batch 4 (lines 1650–2171):** 32×32 pipeline. Critical sub-functions:
- `tmp_eve_buf[16*8=128]`: max access at `[14*8+7]` = `[119]` < 128 ✓
- `tmp_odd_buf[16*8=128]`: max at `[12*8+8+7]` = `[127]` ✓ (boundary exact)
- `tmp_buf[8*32=256]`: max read at `[12*16 + 7*8 + 7]` = `[255]` ✓ (boundary exact)
- `out_arr[32*32=1024]`: four 8-column slices of 256 each, max at `[1023]` ✓
- `input` (32×32 coefficient block = 1024 int16_t): `LD_SH8(input, 4*32, ...)` accesses rows at stride 128; max at `input[7*128+7]` = `input[903]` < 1024 ✓

No `av_malloc`/`memcpy`/`memmove` calls exist. No external-size-driven allocation. All buffers are compile-time fixed sizes aligned to VP9 standard block dimensions. The `eob` parameter only gates which transform variant is dispatched — it is not used as an array index. The `dst_stride` and `dst` pointer come pre-validated from the VP9 decoder's frame management layer.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
