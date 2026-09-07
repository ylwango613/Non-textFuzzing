**Analysis summary:**

`FoFiEncodings.cc` is a purely static data file containing six compile-time initialized tables:
- `fofiType1StandardEncoding[256]` / `fofiType1ExpertEncoding[256]` — const char* arrays
- `fofiType1CStdStrings[391]` — 391 CFF standard glyph name strings (max value ~25 chars, all << 255)
- `fofiType1CISOAdobeCharset[229]` / `fofiType1CExpertCharset[166]` / `fofiType1CExpertSubsetCharset[87]` — Gushort SID tables

**Key findings from context analysis:**

1. **`getString()` (FoFiType1C.cc:3450–3472)**: properly guards `fofiType1CStdStrings[sid]` with `if (sid < 391)` before indexing. Safe.
2. **`buildEncoding()` charset access**: `charset[i]` and `charset[nCodes]` are bounded by `nCodes < nGlyphs`. Safe.
3. **`getGlyphName(int gid)`** (line 171) has no bounds check on `gid < nGlyphs` before `charset[gid]`, but this function has **zero callers** in the entire codebase (confirmed by grep across all `.cc` and `.h` files) — dead code, not exploitable via PDF.
4. **Static charset SID values**: max value in `fofiType1CExpertCharset` is 378 < 391 — within bounds of `fofiType1CStdStrings`.
5. **`gmallocn()` overflow protection**: properly checks `nObjs >= INT_MAX / objSize`.
6. **All string literals** in `fofiType1CStdStrings` are well under 255 bytes, so `strcpy(buf, fofiType1CStdStrings[sid])` into a `char buf[256]` is safe.

No memory safety vulnerabilities are present in or directly triggered by `FoFiEncodings.cc` in the active PDF processing path.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
