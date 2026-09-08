`scan8` has 51 entries (indices 0–50). The 4:2:2 second loop accesses `scan8[i+4]` with a maximum index of 43 — within bounds. All `nnzc` indices derived from those values (max 117) are within the `nnzc[15*8=120]` array. No OOB issue.

**Full analysis summary across all function groups:**

- **IDCT functions** (lines 30–856): All operate on fixed-size 4×4 / 8×8 coefficient blocks (`int16_t block[16]` / `block[64]`) with hardcoded SIMD offsets derived from H264 spec. No attacker-controlled sizes reach malloc/memcpy.
- **`ff_h264_idct8_add_8_mmi` stack manipulation** (lines 180/616): Allocates 32 bytes on `$sp`, uses offsets 0x00–0x18 (24+8=32). Exactly within allocation. Restored before return.
- **`ff_h264_luma_dc_dequant_idct_8_mmi`** (lines 860–1085): Writes `sh` to `output` at offsets 0–0x1e0 (max 480 bytes). Output is `int16_t block[16][16]` = 512 bytes; index 240 is valid. The MIPS branch-delay-slot at line 984 is intentional (writes the 16th DC coefficient) and in-bounds.
- **Weight/biweight functions** (lines 1087–1389): All loop `height` rows over pre-allocated frame buffers. Parameters (`log2_denom`, `weight`, `offset`) are H264-spec-constrained upstream.
- **Deblocking functions** (lines 1391–2413): Operate on frame pixel data with hardcoded 8-byte or 16-byte strips. Stack arrays `stack[0x0a]`/`stack[0x0d]`/`ptmp[0x11]`/`pdat[0x04]` are accessed only at offsets within their declared sizes.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
