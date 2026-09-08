**Batch 1 (lines 1–600) analysis complete:**  
All pixel-comparison functions (`sse4/8/16_c`, `pix_abs*`, `pix_median_abs*`, etc.) operate on caller-supplied buffers with fixed-stride arithmetic. `ff_square_tab[512]` with base pointer `+256` and `uint8_t` difference index (range −255 … +255) yields actual array indices 1–511, all valid.

**Batch 2 (lines 601–1028) analysis complete:**  
Key concern: `rd8x8_c` (line 743) and `bit8x8_c` (line 813) access `s->luma_dc_vlc_length[temp[0] + 256]`, where `temp[0]` is the quantized DC coefficient after `dct_quantize_c`. The table `uni_DCtab_lum_len[512]` is valid for indices 0–511 (i.e., `temp[0]` in [−256, 255]).

**Quantization bound verification:**  
- `dct_quantize_c` computes: `block[0] = (FDCT_DC + q/2) / q` where `q = y_dc_scale << 3`.  
- For `qscale=1`: `y_dc_scale = 8` (from `ff_mpeg4_y_dc_scale_table`), so `q = 64`.  
- FFmpeg's integer FDCT is unnormalized (DC = sum of all 64 inputs). For inputs bounded to ±255: `FDCT_DC ≤ 64 × 255 = 16 320`.  
- Worst-case `block[0]` = `(16 320 + 32) / 64 = 255.5 → 255` (C truncation). Maximum index = 255 + 256 = **511**, the last valid element.  
- Negative case: `(−16 320 + 32) / 64 = −254`. Minimum index = −254 + 256 = **2**. Valid.

The design is intentional: `q <<= 3` exactly cancels the FDCT's unnormalized DC-sum representation, bounding `block[0]` to ±255 for any valid 8-bit pixel data. The `UNI_AC_ENC_INDEX(run, level)` AC accesses (lines 759, 773, 829, 843) are guarded by `(level & (~127)) == 0` (ensuring level ∈ [0,127]) and `run` is bounded by the 64-coefficient scan table; the arrays `uni_mpeg4_intra_rl_len[64×64×2×2 = 16384]` and offset `+128×64 = 8192` still leave 8192 entries, absorbing max index 8191.

**`ff_set_cmp` (lines 443–497):** `type &= 0xFF` + `type >= FF_ARRAY_ELEMS(cmp_func_list)` guard prevents any out-of-bounds array access.

**`WRAPPER8_16_SQ` macro:** correct structural tiling, no size mismatch.

No externally triggerable memory-safety bugs found in this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
