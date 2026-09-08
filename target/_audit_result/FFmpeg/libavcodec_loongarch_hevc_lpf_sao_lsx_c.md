I now have the complete picture. The SAOParams struct is:
```c
typedef struct SAOParams {
    int offset_abs[3][4];       // 48 bytes
    int offset_sign[3][4];      // 48 bytes
    uint8_t band_position[3];   // 3 bytes
    int eo_class[3];            // 12 bytes
    int16_t offset_val[3][5];   // 30 bytes — sao_offset_val points here
    uint8_t type_idx[3];        // follows immediately after
} SAOParams;
```

Every SAO filter function calls `__lsx_vld(sao_offset_val, 0)` loading 16 bytes from a 5-element `int16_t` array (10 bytes). For c=2 (the last component), the extra 6 bytes read: 3 bytes of `type_idx[]` (valid struct fields) and 3 bytes of struct padding — all within mapped memory. After `__lsx_vpickev_b`, only positions 0–4 of the packed table are ever indexed (since valid SAO edge indices are 0–4 via `edge_idx`), so positions 5–7 (containing the OOB data) are never used computationally. No crash, no exploitable data flow.

For the loop and SAO filter height assumptions: HEVC mandates picture dimensions are multiples of `MinCbSizeY` (≥8), ensuring height is always a multiple of 8, so the `height -= 2` loop pattern always terminates correctly.

All SIMD loads of 16 bytes from 4- or 8-pixel-wide sub-regions are safe because `stride_src = 2 * MAX_PB_SIZE + AV_INPUT_BUFFER_PADDING_SIZE = 320 bytes`, providing ample padding within each row's allocation.

After reading all 2488 lines and tracing all call paths, boundary conditions, SIMD operations, and buffer layouts, no externally-triggerable memory safety vulnerability was found in this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
