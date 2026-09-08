After reading and analyzing all 404 lines of `WebFont.cc` in full, tracing every critical path through `makeUnicodeCmapTable`, `makeUnicodeToGID`, `makeType1CWidths`, and `makeCIDType0CWidths`, and verifying the supporting implementations (`gmallocn`, `greallocn`, `getCIDToGIDMap`, `charset` type), the code is consistently safe:

- The counting pass and writing pass over `unicodeToGID` in `makeUnicodeCmapTable` iterate over identical conditions, making `nMappings`/`nSegs` exactly match actual writes; `glyphIdOffset` and `i` never exceed their allocated bounds.
- `gmallocn`/`greallocn` both check `nObjs >= INT_MAX / objSize`, preventing integer-overflow-to-small-allocation.
- `charset` is `Gushort` (max 65535), so `n` in `getCIDToGIDMap` is at most 65535 and `++n = 65536` stays within `int` range and triggers no overflow.
- `widths[gid]` writes in `makeType1CWidths`/`makeCIDType0CWidths` are guarded by `gid < widthsLen`.
- `unicodeToGID` array grows geometrically up to 65536 entries via `greallocn`, within `gmem` protection.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
