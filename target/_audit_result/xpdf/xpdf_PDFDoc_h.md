After completing a full multi-pass audit of `/data/ylwang/non-textfuzz/target/xpdf/xpdf/PDFDoc.h` plus all related implementation files — `PDFDoc.cc` (686 lines), `XRef.cc` (1457 lines), `Catalog.cc`, `AcroForm.cc`, `Annot.cc`, `Page.cc`, `Stream.cc`, `gmem.cc` — here is the final analysis summary before the output block:

**Group 1 – PDFDoc.h inline `getPage*` methods (lines 82-91):** `getPageMediaWidth`, `getPageMediaHeight`, `getPageCropWidth`, `getPageCropHeight`, `getPageRotate` all call `catalog->getPage(page)` without bounds-checking `page`. `Catalog::getPage(int i)` itself also has no bounds check (`pages[i-1]` accessed directly). However, every caller in pdftotext.cc validates `firstPage ≥ 1` and `lastPage ≤ doc->getNumPages()` before iteration, and all internal callers (AcroForm, Annots, Page display) also use pages derived from the bounded iteration. No PDF-controlled path reaches `getPage()` with an out-of-bounds value in the pdftotext attack surface.

**Group 2 – XRef `/Size` and `/Index` allocation:** `readXRefStream` takes `/Size` as `int newSize` directly from the PDF. The `greallocn(entries, newSize, sizeof(XRefEntry))` call is protected by `nObjs >= INT_MAX / objSize` → `gMemError` (process abort, DoS not RCE). `readXRefStreamSection` handles `first + n` overflow by the doubling loop wrapping to negative → `return gFalse`.

**Group 3 – `readXRefTable` offset/gen parsing:** `off` (GFileOffset/`long long`) and `gen` (`int`) accumulation loops have no overflow checks. For `off`, overflow produces a garbage file-seek offset; for `gen`, it produces a wrong generation number. Neither is used as an array index in a way that causes heap corruption.

**Group 4 – `getEmbeddedFileMem`:** Doubling loop with explicit `bufSize > INT_MAX - sizeInc` guard is correct. `streamGetBlock` returns at most `sizeInc` bytes. No overflow.

**Group 5 – `constructXRef` repair mode:** `num` is bounded to < 100,000,000 by the loop condition in `constructObjectEntry`. `constructXRefEntry` with `num = 99,999,999` → `newSize = 100,000,256` → large but non-overflowing `greallocn` call.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
