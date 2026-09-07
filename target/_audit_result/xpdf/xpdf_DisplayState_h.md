Based on my complete analysis of `DisplayState.h` and `DisplayState.cc` along with all relevant context:

- `DisplayState` is a GUI display-state class used exclusively by the `xpdf` GUI viewer via `PDFCore.cc`. It is **not referenced anywhere in `pdftotext` or the `utils/` directory**.
- All data that flows into `DisplayState` (selection rectangles, color modes, zoom, scroll position) originates from **application/user interaction**, not from PDF file content.
- `splashColorModeNComps[colorMode]` is indexed by a valid enum value (0–3, or 0–4 with CMYK), always within the array bounds, and the destination `SplashColor[splashMaxColorComps]` is always sized to match.
- `getSelectRect(int idx)` calls `GList::get(idx)` with no bounds check, but `idx` is application-controlled, not PDF-controlled.
- `splashColorCopy` copies exactly `splashMaxColorComps` bytes between identically-sized `SplashColor` arrays — no overflow possible.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
