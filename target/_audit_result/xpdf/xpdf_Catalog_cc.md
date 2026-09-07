I've now completed a full read of all 1486 lines of Catalog.cc in four batches, examined the memory allocation functions (`greallocn`, `gmallocn`, `gmalloc`, `GString::append`, `GString::size`), and the related header `Catalog.h` and `XRef.h`. Let me summarize what I found before concluding:

**Batch 1 (lines 1–500):**
- `readPageTree()`: `numPages` from PDF accepted only in range 1–50000; out-of-range recounts with `countPageTree`. `greallocn` is called with the final `numPages`. `greallocn` has its own integer-overflow guard (`nObjs >= INT_MAX / objSize → gMemError`). Even if `countPageTree` returns `INT_MAX`, `greallocn` calls `gMemError` → controlled exit, not heap corruption.
- `findDestInTree()`: All `touchedObjs[]` accesses guarded by `getRefNum() < xref->getNumObjects()` bounds checks.

**Batch 2 (lines 500–999):**
- `countPageTree()`: Overflow protection via `n = INT_MAX` sentinel on page count overflow.
- `loadPage2()`: `pages[pg-1]` indexed only with callers supplying `pg` bounded by `numPages`.
- `readEmbeddedFileTree()`: Loop step `++i` (not `i+=2`) is a logic bug—pairs processed correctly bounded; `i+1 < namesObj.arrayGetLength()` ensures OOB never occurs.
- `readFileAttachmentAnnots()`: `if (checkDictLookup(...))` always-true condition is a logic bug; `readEmbeddedFile` type-checks before use.

**Batch 3 (lines 999–1199):**
- `PageLabelNode`: `firstPage = firstPageA + 1` is signed-integer UB if `firstPageA = INT_MAX`, but the resulting value (INT_MIN) does not directly reach any array index.
- `getPageLabel()`: `pageRangeNum = label->start + (pageNum - label->firstPage)` — signed overflow UB when PDF-supplied `/St` or `/Nums` keys are extreme. Result fed to `makeRomanNumeral`/`makeLetterLabel` → very large `m` value → millions of `GString::append` calls → OOM/CPU DoS. However `GString::append` has its own overflow guard (`if (length > INT_MAX - 1) → gMemError`), so heap corruption does not occur.

**Batch 4 (lines 1199–1486):**
- `convertPageLabelToInt` 'D' style: no overflow check on `*n = *n * 10 + digit`, but this function's output is only used in `getPageNumFromPageLabel()`, which in the Qt viewer checks `if (pg <= 0) return`. No array index applied to the overflowed value.
- `checkDictLookup`/`checkArrayGet`: Correct bounds-checked fetching with `touchedObjs`.

**Memory allocation layer:** `greallocn`, `gmallocn` both check `nObjs >= INT_MAX / objSize`. `GString::size()` checks `len > INT_MAX - delta`. All paths abort via `gMemError` rather than proceeding to corrupt the heap.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
