Based on my complete analysis:

**`tif_fax3sm.c`** is entirely auto-generated static constant data (three lookup tables: `TIFFFaxMainTable[128]`, `TIFFFaxWhiteTable[4096]`, `TIFFFaxBlackTable[8192]`). There is no executable code.

**Related files analysis:**
- `tif_fax3.h`: Table index macros use `GetBits(7)→[0..127]`, `GetBits(12)→[0..4095]`, `GetBits(13)→[0..8191]` — all within table bounds
- `tif_fax3.c`: `Fax3SetupState` uses `TIFFSafeMultiply`/`TIFFroundup` with explicit overflow checks; `_TIFFFax3fillruns` bounds-checks each run against `lastx`; run buffer allocation is 2× the minimum needed

**tiffsplit attack path**: tiffsplit calls `TIFFReadRawStrip`/`TIFFReadRawTile` (confirmed at line 251 of tiffsplit.c) — these copy raw compressed bytes without invoking the FAX3 decoder. `Fax3SetupState` is never called; the lookup tables in `tif_fax3sm.c` are never accessed during tiffsplit execution of FAX-compressed TIFFs.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
