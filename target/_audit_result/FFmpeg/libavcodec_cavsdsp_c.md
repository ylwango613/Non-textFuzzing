Having read all 584 lines of `cavsdsp.c` and reviewed the header and calling context, here is my analysis:

**Group 1 (lines 36–186) — deblocking filters**: All functions operate on fixed-size pixel blocks (8 or 16 rows/columns). No dynamic allocation, no user-controlled size parameters.

**Group 2 (lines 194–261) — `cavs_idct8_add_c`**: Casts `block` to `int16_t (*)[8]` (fixed 8×8 = 128 bytes). Intermediate `int` arithmetic stays well within `int` range (max ~2M), though write-back to `int16_t` may truncate — not a memory-safety issue.

**Group 3 (lines 269–543) — motion compensation macros**:
- `CAVS_SUBPIX`: fixed 8-pixel-wide loops with fixed-offset src accesses (`src[-2]` to `src[10]`). Stride is caller-controlled, but frame buffers always have standard codec edge padding.
- `CAVS_SUBPIX_HV` temp buffer: `int16_t temp[8*(8+5)] = temp[104]`. Write loop: 13 iter × 8 = 104 writes (exactly fills temp[0..103]). Read phase: `tmp = temp+16`, reads `tmp[-16]` to `tmp[80+7]` = `temp[0]` to `temp[103]` — within bounds.
- `cavs_filt16_hv_*`: correctly advances src1/dst by `8*stride` between the two row groups.

**Group 4 (lines 550–583) — `ff_cavsdsp_init`**: Only assigns function pointers into a struct.

**Summary**: This file is a pure DSP computation module with no heap allocations, no user-controlled sizes influencing buffer bounds, and no dynamic memory operations whatsoever. All buffer access patterns are bounded by compile-time constants. No memory safety vulnerability can be triggered by crafted media files through this code.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
