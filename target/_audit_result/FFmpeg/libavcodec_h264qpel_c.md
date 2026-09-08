Having read all relevant source files — `h264qpel.c`, `h264qpel_template.c`, `h264qpel.h`, `bit_depth_template.c`, `hpel_template.c`, `pel_template.c` — I performed a thorough analysis:

**Key findings from analysis:**

1. **`pixeltmp tmp[SIZE*(SIZE+5)*sizeof(pixel)]` buffers** (lines 411, 417, 427, 439, 452 of template): For SIZE∈{4,8,16} and all bit depths, the maximum array index accessed by `_hv_lowpass` is exactly `(SIZE+4)*SIZE*sizeof(pixel) + (SIZE-1)`, while the allocated size is `SIZE*(SIZE+5)*sizeof(pixel)` — these are correctly matched with zero overrun.

2. **`uint8_t full[SIZE*(SIZE+5)*sizeof(pixel)]` buffers**: `copy_blockN` copies exactly SIZE+5 rows of SIZE*sizeof(pixel) bytes — perfectly fits the allocated stack arrays.

3. **`h264_qpel16_hv_lowpass` two-call split**: Calls with `tmp` and `tmp+8` for the left/right 8-column halves both stay within the parent array (max index 399 vs array size 672 for BIT_DEPTH>8).

4. **`ff_h264qpel_init` function table**: Indices IDX∈{0,1,2} and [1..15] are all within the declared `[3][16]` arrays; no untrusted data controls the table index.

5. **No externally-controlled sizes**: All buffer dimensions (`SIZE`, `BIT_DEPTH`) are compile-time template constants; no field from a media container flows directly into buffer allocation or array indexing in this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
