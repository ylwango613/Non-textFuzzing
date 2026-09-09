After exhaustive analysis of every code path:

**`get_block()` — PUT_COEFF array accesses:**
- `coeff = get_bits(gb, 6)` → always 0–63.
- `scan[]` is `uint8_t[64]`; `idct_permutation[]` is a permutation of 0–63; so `scan[coeff]` ∈ [0,63].
- `block` is `int16_t[64]`, so `block[scan[coeff]]` is always in bounds.
- The 8-bit loop has no `break`, so after it `coeff = 0`; the terminal `PUT_COEFF(dc)` accesses `scan[0]`, valid.

**`ff_rtjpeg_decode_frame_yuv420()` — plane pointer arithmetic:**
- Row-advance formula: total advance for Y = `w*16 + 16*(linesize[0] - w) = 16*linesize[0]` — correct.
- Chroma: `w*8 + 8*(linesize[1] - w) = 8*linesize[1]` — correct.
- `nuv.c` enforces `c->width >= 16 && c->height >= 16` before calling.

**Bitstream bounds:**
- All three coefficient phases (`coeff<<1`, `coeff<<2`, `coeff<<3`) are checked before reading; max value 63<<3=504 fits in `int` without overflow.
- `ALIGN` skips land inside AV_INPUT_BUFFER_PADDING_SIZE zeroed bytes; LZO path explicitly sets padding at line 223.

**Quantization tables:**
- Read as 64 `uint32_t` values from the packet; used only as multipliers, not as indices.

No externally-triggerable memory-safety defect found in this file or its direct call chain.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
