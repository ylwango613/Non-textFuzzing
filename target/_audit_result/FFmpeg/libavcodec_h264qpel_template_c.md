I've now read the entire 491-line file plus all three included template files and `h264qpel.c`. Let me summarize the analysis:

**`h264qpel_template.c` analysis complete:**

1. **Buffer sizes**: All stack buffers use compile-time constant expressions — SIZE ∈ {4, 8, 16} and `sizeof(pixel)` ∈ {1 (8-bit), 2 (9/10/12/14-bit)}. Max sizes: `full[16*21*2 = 672]`, `tmp[672 pixeltmp elements]`, `halfH/halfHV/halfV[512]`. No dynamic user-controlled sizes.

2. **`pixeltmp` overflow check**: `int16_t` for BIT_DEPTH 8/9/10, `int32_t` for 12/14. For BIT_DEPTH=10, the `pad = -10*1023 = -10230` is deliberately chosen so that intermediate `tmp` values stay within `[-20460, 32736]` — safely fitting in `int16_t` (range ±32767). No integer overflow in temporaries.

3. **Negative indexing (`src[-2*srcStride]` etc.)**: These read rows before the provided `src` pointer, which relies on frame border padding. Confirmed: `h264_mb.c` calls `vdsp.emulated_edge_mc()` at lines 241, 260, 274, 301, 312 before any QPEL call, guaranteeing at least 2 rows of padding.

4. **`tmp` pointer arithmetic in hv_lowpass**: After first loop writes `h+5` rows, `tmp -= tmpStride*(h+5-2)` resets it to row 2. Second loop reads `tmp[-2*tmpStride]` through `tmp[(h+2)*tmpStride + w-1]`, all within the originally allocated `SIZE*(SIZE+5)*sizeof(pixel)` elements.

5. **`full_mid` pointer**: Set to `full + SIZE*2*sizeof(pixel)` bytes, so `full_mid[-2*srcStride]` in pixel terms maps to `full[0]`. The `copy_block` call fills exactly `SIZE*(SIZE+5)*sizeof(pixel)` bytes starting at `full[0]`, matching the array size perfectly.

No externally-triggerable memory safety vulnerabilities were found.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
