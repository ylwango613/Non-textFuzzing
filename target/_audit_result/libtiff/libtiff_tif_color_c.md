Having read and analyzed the complete `tif_color.c` (288 lines), let me verify the allocation arithmetic one final time:

**Group 1 (lines 45–71): `TIFFCIELabToXYZ`**
- Inputs `l` (uint32), `a`, `b` (int32) from TIFF pixel data feed into pure floating-point arithmetic. No array indexing. No memory safety risk.

**Group 2 (lines 78–118): `TIFFXYZToRGB`**
- Lines 91–98: `Yr/Yg/Yb` are clipped with `TIFFmax(Yr, d_Y0R)` (lower bound) and `TIFFmin(Yr, d_YCR)` (upper bound).
- Lines 101–111: Index `i = (int)((Yr - d_Y0R) / rstep)`. After the lower-bound clip, `Yr >= d_Y0R`, so numerator ≥ 0. For `display_sRGB` `rstep = (100.0 - 1.0)/1500 > 0`, so `i ≥ 0`. Upper-bound: `i = TIFFmin(cielab->range, i)` → `i ≤ 1500`. Arrays `Yr2r/Yg2g/Yb2b` have `CIELABTORGB_TABLE_RANGE + 1 = 1501` elements. All accesses in `[0, 1500]`. ✓

**Group 3 (lines 124–168): `TIFFCIELabToRGBInit`**
- All three loops are bounded `[0, CIELABTORGB_TABLE_RANGE]` (1500 inclusive), writing into 1501-element statically-sized arrays. ✓

**Group 4 (lines 183–198): `TIFFYCbCrtoRGB`**
- `Y = HICLAMP(Y, 255)` → `Y ∈ [0, 255]`; `Cb/Cr = CLAMP(…, 0, 255)` → indices for `Y_tab`, `Cr_r_tab`, `Cb_b_tab`, `Cr_g_tab`, `Cb_g_tab` all bounded to `[0, 255]`. Each table has 256 entries. ✓

**Group 5 (lines 217–272): `TIFFYCbCrToRGBInit`**
- Allocation: `TIFFroundup(sizeof(TIFFYCbCrToRGB), sizeof(long)) + 4×256×1 + 2×256×4 + 3×256×4 = TIFFroundup + 6144 bytes`
- Table layout in init: clamptab (1024 bytes) + Cr_r_tab (1024) + Cb_b_tab (1024) + Cr_g_tab (1024) + Cb_g_tab (1024) + Y_tab (1024) = 6144 bytes. Exact match. ✓
- `Code2V` macro protects against divide-by-zero via ternary `((RW)-(RB)) ? … : 1`. ✓

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
