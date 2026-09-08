**Batch findings summary (all 10 segments reviewed):**

- Blend functions (1-500): purely arithmetic, no memory indexing issues
- Color/font loading (500-1750): `gmallocn` with validated sizes; no OOB writes
- Tiling pattern (1750-2220): `tileW > INT_MAX/tileH` check before use; safe
- Type3 glyph cache (2495-2830): `i = glyphW*glyphH` computed before overflow check is UB but immediately caught by `glyphW > INT_MAX/glyphH`; `memcpy` size matches bitmap dimensions exactly
- Image source callbacks (2990-3360): `imageLookup2Src` index `k = (p[0] << bpc) + p[1]` is bounded by construction — when `bpc = log₂(n)`, max k = n²-1 which equals the lookup table size
- Masked/soft-masked image (3360-3980): mask bitmap dimensions = image dimensions; row traversal stays in bounds
- `buildColorMapLookupTable2Idx` (4084-4207): allocation size `n*n` matches exactly the max k index
- `setSoftMask` (4587-4756): `tx+tw <= bw` and `ty+th <= bh` enforced by `beginTransparencyGroup` clamping; no OOB write
- Blend mode dispatch (line 1135): `splashOutBlendFuncs` has exactly 16 entries matching the 16 `GfxBlendMode` enum values
- `maskColors` (Gfx.cc caller): array is `2*gfxColorMaxComps` local stack; uninitialized reads of higher indices possible but reading only uninitialized stack — no memory corruption

No exploitable memory safety vulnerability found in this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
