After thoroughly reviewing the complete file and all usage sites:

- `FontEncodingTables.h` is a 20-line pure declaration header — 7 `extern const char *table[]` symbols, no code, no logic.
- The `.cc` implementation defines all 7 tables as exactly `[256]` static constant arrays.
- Every consumer (GfxFont.cc, Annot.cc, GlobalParams.cc, SplashOutputDev.cc, FoFiType1C.cc, FoFiType1.cc) accesses these tables only via loops bounded by 256, explicit `& 0xff` masking, or per-element bounds checks (`code >= 0 && code < 256`).
- `getCharProcNF(code,...)` at GfxFont.cc:1647 accesses `enc[code]` without a bounds check, but `code` always originates from `*s & 0xff` in `Gfx8BitFont::getNextChar()`, guaranteeing [0,255].
- FoFiType1C `buildEncoding()` range format properly guards writes with `if (c < 256)`.
- FoFiType1 `parse()` unsigned `code` integer may theoretically wrap, but the `if (code < 256)` guard still applies post-wrap — no reliably exploitable OOB write.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
