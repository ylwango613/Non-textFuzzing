Having now read the complete file (`UnicodeMapTables.h`, 367 lines) and the full implementation context (`UnicodeMap.cc`, `UnicodeMap.h`), I can make a thorough assessment.

**Group 1 — `UnicodeMapTables.h` static data (lines 1–367)**
All `nBytes` fields in the static range tables are 1, 2, or 3. The `code` values are within the 32-bit `Guint` type. No values can cause overflow. These tables are embedded in the binary as resident maps and cannot be influenced by a PDF file.

**Group 2 — `UnicodeMap::mapUnicode()` (UnicodeMap.cc:179–224)**
The ranges path has `if (n > bufSize) return 0;` (line 201–203). The eMaps path (lines 213–220) is **missing** this check — `n = eMaps[i].nBytes` and then `buf[j] = eMaps[i].code[j]` for `j = 0..n-1` without bounding by `bufSize`. Callers use `char buf[8]`, but `UnicodeMapExt.code[maxExtCode]` holds up to 16 bytes, so any matched eMap with `nBytes > 8` would cause a stack OOB write. However, eMaps are populated via `UnicodeMap::parse()` which reads from system UnicodeMap configuration files (controlled by xpdfrc), **not** from the PDF file itself.

**Group 3 — `UnicodeMap::parse()` heap OOB (UnicodeMap.cc:86–89)**
When `nBytes = strlen(tok3)/2 > maxExtCode (16)`, the loop `eMap->code[i] = (char)x` writes beyond the 16-byte `code[]` array. Same attack vector: requires attacker-controlled UnicodeMap files, not a crafted PDF.

**Attack-path determination**: `GlobalParams::getUnicodeMapFile()` (line 2726–2738) only opens files whose paths come from `unicodeMaps` lookup table in xpdfrc — these are system configuration files entirely outside the PDF's control. A crafted PDF alone cannot cause `UnicodeMap::parse()` to be called with a malicious file, nor can it deliver an eMaps entry with dangerous `nBytes`. The attack surface specified (crafted PDF → pdftotext) does not reach these code paths without also controlling system configuration files.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
