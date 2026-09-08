**Summary of analysis across all 2052 lines:**

- **Lines 0–600**: Document loading, page display, history management. The `addToHistory()` Windows path uses `gmallocn(nChars, sizeof(wchar_t))` where `nChars` is bounded by OS path limits—safe.
- **Lines 600–1200**: Navigation, scroll/zoom, selection state management. `zoomToCurrentWidth()` line 912–913 uses `w` (a double accumulator) as the loop condition/increment variable instead of `page`—logic bug, not memory-safety.
- **Lines 1200–1800**: Text extraction, find/search. `gmallocn(len, sizeof(Unicode))` at line 1470 uses `strlen(s)` from a UI search string (not PDF content). The `rect` pointer at line 1581 is accessed only in the `!next` branch where `state->hasSelection()` ensures it was assigned—no NULL dereference.
- **Lines 1800–2052**: Link/annotation look-up, text cache management, bbox computation. Pure delegation and integer arithmetic, no unsafe patterns.

**Conclusion:** PDFCore.cc is a high-level viewer state coordinator. It has only two `gmallocn` calls (both safe), no `memcpy` with file-controlled sizes, and no direct array indexing with PDF-supplied values. All dangerous PDF operations (stream decoding, font parsing, xref handling) are fully delegated to other modules.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
