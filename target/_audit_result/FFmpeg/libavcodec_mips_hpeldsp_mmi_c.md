Analysis complete across all 1119 lines in two batches. Summary of findings:

**Batch 1 (lines 1–600):** Functions `ff_put_pixels{4,8,16}_8_mmi`, `ff_avg_pixels{4,8,16}_8_mmi`, and the `_l2_` family. All use pre-allocated caller-provided buffers; no `av_malloc`/`memcpy` with attacker-controlled sizes. Loop structure is `bnez` (check at bottom) decrementing `h` by 2 or 4. The `h` values in all call sites are hardcoded literals (8, 16) in `vc1dsp_mmi.c`/`h264qpel_mmi.c` or constrained by codec macroblock dimensions (always multiples of 4).

**Batch 2 (lines 600–1119):** `ff_put_no_rnd_pixels*`, `ff_put_pixels*_xy2_8_mmi`, `ff_avg_pixels*_xy2_8_mmi`. The C-path functions use `AV_RN32` (unaligned 4-byte reads) on caller-provided pixel pointers; pointer arithmetic (`pixels += 4 - line_size * (h+1)`) is correct for the 4+4=8-pixel two-pass pattern. No allocation, no size-from-file arithmetic.

**Key facts:**
- No `av_malloc`/`realloc`/`memcpy` with externally-derived sizes → no integer-overflow-to-underalloc
- All buffers are pre-allocated by the motion compensation layer (block = macroblock buffer, pixels = reference frame buffer)
- `h` values are constrained to `{4, 8, 16}` (multiples of 4) by codec; function pointer dispatch indices come from validated `mb_type`, not the raw bitstream int
- No container/bitstream data is parsed in this file — it is a pure SIMD compute layer

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
