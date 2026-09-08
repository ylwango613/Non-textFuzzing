I've now completed a thorough multi-pass audit of XFAScanner.cc (686 lines) and all its key dependencies:

**Batch 1 (lines 1–400):** Analyzed `readXFAStreams`, `scanFormValues`, `scanFormNode`, the beginning of `scanNode`, and `scanField`. Traced ownership of `GString*` borrowed/owned pointers throughout. Checked `GHash::add()` duplicate-key behavior against `deleteGHash` teardown — no double-free because `fields` uses `deleteKeys=false` and `deleteGHash` deletes values first.

**Batch 2 (lines 400–686):** Reviewed `getDatasetsValue` (recursion bounded by dots in name string), `getFieldBarcodeInfo` (wideNarrowRatio parsing, `(int)(colon-s)` always ≥ 0), `getMeasurement` (pure arithmetic, no array accesses), `getFieldLayoutInfo/PictureInfo` (attribute parsing, all heap-allocated GStrings).

**Zoox.cc analysis:** Reviewed `appendUTF8` (hex/decimal overflow loops produce unsigned wrap-around, values >0x7fffffff silently discarded — no heap write), `parseAttr`/`parseCharData` entity expansion (GString::append properly bounds-checked), `parseCDSect` loop bound `parsePtr < parseEnd - 3` (correct pointer arithmetic), `parseContent`↔`parseElement` mutual recursion (stack exhaustion DoS, not heap corruption).

**GString/GHash/gmem:** `GString::resize()` overflow-checked via `size()` function; `GString::append()` checks `length > INT_MAX - n`; `gmallocn` checks `nObjs >= INT_MAX / objSize`. All size calculations protected.

**Key non-issues verified:**
- `nameIdx` NULL-dereference at line 270: impossible because when `nameIdx=NULL` (initial call only), `elem` is always "template" → `nodeName=NULL` → `if (nodeName)` block never entered.
- `formValues` value GStrings: properly freed by `deleteGHash(formValues, GString)` before scanner teardown.
- `wideNarrowRatio` division by zero: handled explicitly with `if (den == 0)` guard.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
