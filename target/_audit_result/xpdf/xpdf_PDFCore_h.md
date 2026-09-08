After thoroughly reading PDFCore.h (387 lines) and its full implementation PDFCore.cc (2052 lines) in batches, I analyzed:

**Batch 1 (PDFCore.h):** Fixed-size `history[pdfHistorySize=50]` array, navigation/selection methods, coordinate conversion.

**Batch 2-3 (PDFCore.cc constructor/destructor):** `historyCur` initialized to 49, proper modular wrapping in all history mutations, proper bounds in destructor.

**Batch 4-5 (addToHistory/goForward/goBackward):** Modular arithmetic `(++historyCur == pdfHistorySize) → historyCur=0` and `(--historyCur < 0) → historyCur=pdfHistorySize-1`. `historyBLen` capped at `pdfHistorySize`. Invariant `historyBLen + historyFLen ≤ pdfHistorySize` maintained.

**Batch 6 (find/findU):** `gmallocn(len, sizeof(Unicode))` - `gmallocn` has overflow guard `nObjs >= INT_MAX / objSize`. `len=0` handled before use.

**Batch 7 (gmallocn):** Confirmed integer overflow check: `nObjs >= INT_MAX / objSize`.

**Batch 8 (loadText/loadLinks):** Cache pattern with delete-before-reload is safe.

**Batch 9 (splashColorModeNComps):** Array indexed by `SplashColorMode` enum (0-3), `SplashColor` buffer is sized `splashMaxColorComps`. Color mode is not attacker-controlled via PDF content.

**Batch 10 (setLinearSelection/checkInvalidate):** Coordinate math stays bounded by window dimensions. Selection list uses heap-allocated GList with `append`.

No direct PDF-parse-to-memory-corruption path found in this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
