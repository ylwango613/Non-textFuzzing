The mathematical proof is conclusive: `av_image_check_size2`'s constraint (`stride_check * (h+128) < INT_MAX`) ensures that `stride_aasc * height` never reaches INT_MAX for any accepted frame dimensions across all three pixel depths. The maximum achievable product is ~2.11 billion vs INT_MAX = 2.147 billion — the overflow at line 108 is provably unreachable.

Complete analysis summary:
- **Lines 54-59** (palette init): `FFMIN(extradata_size, AVPALETTE_SIZE)` correctly caps reads; `palette[AVPALETTE_COUNT]` = 1024 bytes = AVPALETTE_SIZE, no overflow.
- **Line 107-108** (`stride * avctx->height`): Signed integer overflow is mathematically impossible given `av_image_check_size2`'s conservative dimension limits (proven above).
- **Line 111** (`memcpy` with `avctx->width * psize`): Same dimension constraints mean `width * psize` cannot overflow past INT_MAX within accepted frames; destination is within allocated frame linesize.
- **Line 131** (`memcpy` to `data[1]`): `palette_size ≤ AVPALETTE_SIZE`; `data[1]` for PAL8 is exactly AVPALETTE_SIZE. Safe.
- **msrledec.c `msrle_decode_8_16_24_32`**: All writes bounded by `output_end`; reads via `bytestream2_*` with remaining-bytes guards.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
