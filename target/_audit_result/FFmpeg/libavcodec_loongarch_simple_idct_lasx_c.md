After reading all 297 lines across three functions and the supporting init/header files, here is the complete analysis:

**Findings per function group:**

- `ff_simple_idct_lasx` (lines 177–198): The `LASX_IDCTROWCONDDC` macro loads from `block` at fixed byte offsets 0, 32, 64, 96 with 32-byte LASX vectors → total 128 bytes = exactly 64 × `sizeof(int16_t)` (one standard 8×8 DCT block). Stores (`__lasx_xvst`) write back to the same four fixed offsets. No dynamic size, no user-controlled index.

- `ff_simple_idct_put_lasx` (lines 200–232): After IDCT, writes 8 bytes to each of 8 rows of `dst` via `__lasx_xvstelm_d`. Stride arithmetic (`dst_stride << 1`, `<< 2`, `+ dst_stride`) uses `ptrdiff_t` (64-bit); for any real video frame width the value cannot overflow. Stride comes from the codec framework, not directly from the container bytestream at this call site.

- `ff_simple_idct_add_lasx` (lines 234–297): Reads 8 rows of existing pixel data via `__lasx_xvldrepl_d` (8 bytes each), adds IDCT output, clips to [0,255], packs back to `uint8_t` and writes 8 rows. All access points are at strictly counted, fixed offsets relative to `dst`/`dst1`; no user-controlled dimension in the memory arithmetic.

- Registration (idctdsp_init_loongarch.c): These functions are only registered when `avctx->lowres ∉ {1,2,3}`, `bits_per_raw_sample ∉ {10,12}`, and `idct_algo == FF_IDCT_AUTO` — further restricting the attack surface.

No dynamic allocation, no untrusted size in any memory operation, all buffer accesses are at compile-time-fixed offsets for a well-defined 8×8 block.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
