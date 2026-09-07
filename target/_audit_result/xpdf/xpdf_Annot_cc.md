After a complete multi-pass review of Annot.cc (1549 lines) and all key supporting code, here is my final assessment:

**Batch 1 (lines 1–500):** Constructor parsing of Rect, border style, appearance. `gmallocn(borderDashLength, sizeof(double))` is protected by `gmallocn`'s overflow check; `arrayGetLength()` is always ≥ 0 since `Array::length` only grows. No OOB.

**Batch 2 (lines 500–1000):** `generatePolyLine/PolygonAppearance` — all vertex accesses are guarded by `i+1 < arrayGetLength()`. GString `appendf` calls are protected by `GString::resize → size()` integer overflow check.

**Batch 3 (lines 1000–1302):** `drawText` — Unicode BOM path constructs `text2` as a shorter string; the width-computation loop bounds on `text2->getLength()` < `text->getLength()`, so `text->getChar(i)` accesses are always in range. `daToks->get(tmPos+5)` where `tmPos = i-6` and `i < daToks->getLength()` → index is always within bounds.

**Batch 4 (lines 1302–1549):** `loadFormFieldRefs` — `formFieldRefs[getRefNum()]` write is only reached if `getRefNum() < formFieldRefsSize` (post-growth). Parser validates ref nums ≥ 0 (Parser.cc:112-116). Realloc size bounded by `INT_MAX/2*2`. No OOB. `loadAnnots` — `formFieldRefs[annotRef.num]` is doubly guarded by `annotRef.num >= 0 && annotRef.num < formFieldRefsSize`.

All `gmallocn`/`grealloc`/`GString` operations have integer-overflow guards that abort on invalid sizes.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
