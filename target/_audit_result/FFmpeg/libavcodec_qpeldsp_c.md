After a complete multi-pass analysis of `qpeldsp.c` (819 lines) and all its included templates (`hpel_template.c`, `pel_template.c`, `qpel_template.c`, `copy_block.h`), here are my findings:

**Group 1 (lines 43–691): QPEL_MC macro expansion — all fixed-size stack buffers**

Checked every intermediate buffer in every qpel8 and qpel16 motion compensation variant:

- `halfH[72]` (qpel8): written by `mpeg4_qpel8_h_lowpass(..., h=9)` → 9×8 = 72 bytes ✓; read by `mpeg4_qpel8_v_lowpass(halfH, ..., srcStride=8)` → max read = halfH[64+7] = halfH[71] ✓
- `halfH[272]` (qpel16): written by `mpeg4_qpel16_h_lowpass(..., h=17)` → 17×16 = 272 bytes ✓; read by `mpeg4_qpel16_v_lowpass(halfH, ..., srcStride=16)` → max read = halfH[256+15] = halfH[271] ✓
- `full[16*9]` = 144: `copy_block9(full, src, dstStride=16, ...)` → max write = full[8×16+8] = full[136] < 144 ✓
- `full[24*17]` = 408: `copy_block17(full, src, dstStride=24, ...)` → max write = full[16×24+16] = full[400] < 408 ✓
- All pointer arithmetic with `+1`, `+8`, `+16`, `+17`, `+24`, `+25` offsets into `full` verified to stay in bounds.

**Group 2 (lines 739–782): DIRAC_MC macro — `h` parameter**

`h` comes from the Dirac decoder's internal block size structures; no allocation is done here, just per-row iterations on existing frame reference buffers. No independently-triggerable OOB within this file.

**Group 3 (lines 784–818): `ff_qpeldsp_init`**

Only function pointer table initialization — no memory operations.

**Overall assessment:** The file is pure stack-based DSP computation with hard-coded block sizes (8×8 and 16×16). Every intermediate buffer size exactly matches the number of rows and columns written to it. No heap allocations, no external-input-derived size parameters, no integer arithmetic on attacker-controlled values. The safety of the `src` pointer and `stride` depends on callers (frame allocation + `emulated_edge_mc` in `mpegvideo_motion.c`), not on anything in this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
