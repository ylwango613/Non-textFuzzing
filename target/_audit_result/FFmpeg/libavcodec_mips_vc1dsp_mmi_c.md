After reading all 2463 lines in full and conducting targeted searches, my analysis is complete.

This file is a MIPS MMI–optimized leaf DSP library for VC-1 inverse transforms, overlap filtering, loop deblocking, and motion compensation. Key observations across every function group:

- **No `av_malloc`/`av_realloc`/`memcpy`** — zero dynamic allocation or copying driven by external sizes.
- **All SIMD block accesses use hardcoded byte offsets** into fixed-size `int16_t block[64]` (128 bytes) or local stack arrays with compile-time-known sizes (e.g., `coeff[64]`, `temp[64]`, `LOCAL_ALIGNED(16, int16_t, tmp, [12*8])`). Every access falls within those bounds.
- **`hmode`/`vmode` are not attacker-controlled at this level**: they are hardcoded to 0–3 via `DECLARE_FUNCTION(a,b)` macros; all function-pointer table entries are exactly 4 elements.
- **`x`/`y` in chroma MC functions** are guarded by `av_assert2(x < 8 && y < 8 && x >= 0 && y >= 0)` before any weight computation.
- **`linesize`/`stride` parameters** come from the decoder's frame allocation layer, not directly from the bitstream byte stream.
- **Overlap transform writes** (`src[-2] = a - d1`, `src[1] = d + d1`) are intentional truncation per the VC-1 spec; they do not cause OOB writes — they write to already-validated adjacent pixel locations.
- **`vc1_put_ver_16b_*` and MSPEL filter functions** write into `tmp[12*8]` (192 bytes) with maximum write offset 0xB8+8 = 192 bytes — exact fit with no overflow.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
