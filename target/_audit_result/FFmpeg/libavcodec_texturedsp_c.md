After completing a thorough multi-pass audit of `texturedsp.c` and all its callers (dds.c, hapdec.c, dxv.c, vbndec.c), including the template in `texturedsp_template.c`, here is my analysis summary before the final determination:

**texturedsp.c functions:**
- All block decompression functions (`dxt1_block_internal`, `dxt3_block_internal`, `dxt5_block_internal`, `rgtc1_block_internal`, `rgtc2_block_internal`, etc.) read from exactly 8 or 16 fixed-size bytes and write to a 4×4 pixel region using caller-provided stride. No dynamic allocation, no untrusted sizes used internally.
- `decompress_indices` reads exactly 6 bytes (2 blocks × 3 bytes), writes 16 bytes into a stack array of size 16. All accesses bounded.
- `extract_color`: all arithmetic is bounded; `colors[code & 3]` always indexes [0..3]. `ycocg2rgba`: divisor `s = (b>>3)+1 ≥ 1` always, no div-by-zero.
- Array index `alpha_indices[x + y*4]`, `indices[x + y*4]` always 0..15; `color_tab[i]` always 0..7.

**Callers:**
- **dds.c**: `size = (coded_height/4) * (coded_width/4) * tex_ratio` computed as int; bounded by `av_image_check_size2` limits (~268M pixels max), so no int overflow. Buffer adequacy check before decompression is correct.
- **hapdec.c**: `tex_size` check guards the `tex_data.in` buffer; slice counts use `av_clip`; all safe.
- **dxv.c**: `tex_size` allocation via `av_fast_realloc` with padding; all block accesses within allocated bounds including the `+tex_ratio/2` pointer offsets.
- **vbndec.c**: `linesize * coded_height` bounded by image size limits; data adequacy checked before decompression.
- **Template (texturedsp_template.c)**: slice distribution arithmetic correct; `(off + x) * tex_ratio` stays within pre-validated buffer; negative-stride (VBN) handled correctly by starting at last row.

No externally triggerable memory-safety vulnerabilities were found in `texturedsp.c` or in the texturedsp framework as consumed by its callers.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
