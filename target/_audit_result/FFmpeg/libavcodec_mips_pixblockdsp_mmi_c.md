After fully reading `pixblockdsp_mmi.c` (135 lines), both referenced header files, and tracing the callers through `pixblockdsp.c` and `pixblockdsp_init_mips.c`, the analysis is:

**`ff_get_pixels_8_mmi` (lines 28–95):** Reads exactly 8 rows × 8 bytes from `pixels` (via `MMI_LDC1`/`MMI_LDXC1` in pairs, advancing by `stride×2` four times). Writes exactly 16 stores × 8 bytes each = 128 bytes to `block`. This matches the fixed 8×8 int16_t DCT block contract (64 elements × 2 bytes = 128 bytes).

**`ff_diff_pixels_mmi` (lines 97–135):** Loops exactly 8 times, each iteration reading 8 bytes from `src1` and `src2`, writing 16 bytes to `block`, advancing `block` by 0x10. Total block write: 128 bytes. Same fixed-size contract.

Neither function performs any allocation, reads any size field from a media container, or contains dynamic indexing. The `stride << 1` in `ff_get_pixels_8_mmi` is a compile-time-traceable signed shift, and `stride` is validated by the frame layout layer before reaching these SIMD routines. All buffer sizes are fixed at 128 bytes per the 8×8 DCT block convention upheld by every caller.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
