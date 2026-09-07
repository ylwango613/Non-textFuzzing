**Analysis summary for DisplayState.cc:**

- **Lines 1–220 (complete file)**: Manages display/GUI state for the xpdf viewer. No PDF data is parsed here.
- **Constructor loop (lines 41–53)**: `splashColorModeNComps[colorMode]` returns at most 3 (no CMYK) or 4 (CMYK); `SplashColor` is `Guchar[3]` or `Guchar[4]` respectively — no OOB.
- **`getSelectRect(idx)` (line 204–206)**: No bounds check, but not in the PDF-parsing path; called from internal GUI logic only.
- **`setSelection()` (lines 165–191)**: Memory managed correctly via `deleteGList`.
- **No PDF-controlled data path**: This file is GUI-only (`PDFCore.cc`, `TileMap.cc`, `TileCache.cc`, `TileCompositor.cc` use it). `pdftotext` does not invoke `DisplayState` at all — the class is part of the viewer, not the text-extraction tool.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
