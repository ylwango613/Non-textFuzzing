Having completed a full multi-pass read of all 1550 lines of `Annot.cc` plus `Annot.h`, the `gmallocn`/`grealloc` implementations in `gmem.cc`, `GList.cc`, and the `Object` class, I now summarize the findings:

**Pass 1 findings (lines 1-300):** `gmallocn(borderDashLength, sizeof(double))` — `gmallocn` has an explicit guard: `nObjs >= INT_MAX / objSize` → safe. `borderColor[4]` is a 4-element stack array always fully initialized; `AnnotBorderStyle` constructor always accesses `colorA[0..3]` against that full 4-element buffer — safe.

**Pass 2 findings (lines 300-700):** Appearance generation for Line/PolyLine/Polygon — no unbounded writes; `GString::appendf` calls use all literal format strings and floating-point arguments.

**Pass 3 findings (lines 700-1100):** `drawText` at line 1215 iterates over `text2->getLength()` but reads `text->getChar(i)` — the Unicode-converted `text2` is at most `(text->length - 2) / 2` chars, so `i` always stays within bounds of the longer `text`. Logic bug (wrong character widths), not OOB. `winAnsiEncoding` is a 256-element array accessed with `& 0xff` — safe.

**Pass 4 findings (lines 1100-1550):** `formFieldRefs` dynamic growth uses `grealloc` then manually zeros bytes from old size to new size — correct. `Object::free()` on default-constructed `Object` hits `default: break` (type is `objNone`) — safe. `Annots::add` at line 1527 accesses `pageAnnots[page-1]` without calling `loadAnnots` first (potential NULL deref crash), but this is internal API not directly driven by PDF byte parsing.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
