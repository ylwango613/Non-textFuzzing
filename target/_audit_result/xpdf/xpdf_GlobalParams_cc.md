**Analysis complete across all 4260 lines (9 batches).**

**Batch-by-batch findings summary:**

- **Lines 1-500**: `mungeName1/2/3()`, `match()`, `scanWindowsFonts()` — The Windows registry scan at lines 515-518 has a genuine OOB read (`data + strlen(data) - 4` without checking strlen ≥ 4 when `dataLen > 0` allows `strlen(data) < 4`). However, this is `#ifdef _WIN32` only and triggered by registry content at startup, NOT by any crafted PDF file.
- **Lines 500-1000**: `makeWindowsFont()` at line 559 has similar unchecked strlen pattern (`path + strlen(path) - 4`) — same: Windows-only, not PDF-triggered.
- **Lines 1000-1500**: `parseFile()`/`parseLine()`/`parseLineTokens()` — Config file (xpdfrc) parsing with fixed buf[512]. `getLine()` (confirmed at goo/gfile.cc:725) reads at most `size-1` bytes, so no overflow. These parse the xpdfrc config, not PDF data.
- **Lines 1500-2000**: `parseBind/Unbind/Key/PopupMenuCmd()` — Config file parsing only. No raw buffer ops.
- **Lines 2000-2500**: `parseKey()`, `parsePopupMenuCmd()`, `parseZoomScaleFactor()` — All config-file parsing, safe.
- **Lines 2500-3000**: `setupBaseFonts()`, accessors — Font file discovery using safe GString/appendToPath ops. No raw buffer overflows.
- **Lines 3000-4260**: Accessor/setter functions — All thread-safe getters/setters with no raw buffer operations.

**Conclusion**: GlobalParams.cc is a configuration parameter store. None of its parsing routines are invoked by processing a crafted PDF file — they run at startup from the xpdfrc config file. The functions called during PDF processing (getCIDToUnicode, findFontFile, isDroppedFont, etc.) perform only safe hash-table lookups and GString path operations. No memory safety vulnerabilities reachable via a crafted PDF file exist in this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
