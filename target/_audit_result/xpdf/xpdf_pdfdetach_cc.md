After thoroughly reading `pdfdetach.cc` (231 lines, read in full) and tracing every called function, here is my analysis:

**`mapUTF8` (UTF8.cc:12)**: All four branches check `bufSize` before writing. Max output 4 bytes into `uBuf[8]` — safe.

**`UnicodeMap::mapUnicode` eMaps path (UnicodeMap.cc:213-220)**: The ranges path at line 200-202 has `if (n > bufSize) return 0;`, but the eMaps path writes `buf[j]` for `j = 0..n-1` with no `bufSize` check. `UnicodeMapExt::code` is `char code[16]` (`maxExtCode=16`), so `nBytes` up to 16 could overflow `uBuf[8]`. However, eMaps are loaded from config files, not from the PDF — the default `UTF-8` encoding is `unicodeMapFunc` kind and calls `mapUTF8` directly, bypassing the eMaps path entirely.

**`GString::append` (GString.cc:248)**: Has `if (lengthA < 0 || length > INT_MAX - lengthA)` guard — safe.

**`saveEmbeddedFile2` (PDFDoc.cc:642)**: Reads stream into `char buf[4096]` via `streamGetBlock(buf, sizeof(buf))` — `getBlock` is bounded by the `size` parameter — safe.

**`getEmbeddedFileMem` (PDFDoc.cc:659)**: Has `if (bufSize > INT_MAX - sizeInc)` guard — safe.

**`TextString::expand` (TextString.cc:156)**: Has `delta > INT_MAX - len` guard — safe.

**NULL/bounds on `name`**: `getEmbeddedFileName(idx)` and `getEmbeddedFileNameLength(idx)` both read from the same `TextString`, so they're consistent. Loop guard `for (j = 0; j < nameLen; ++j)` prevents any access when `nameLen == 0`.

All paths reachable from a crafted PDF with default settings are safe. The only bug found (`mapUnicode` eMaps path missing `bufSize` check) requires an attacker-controlled custom unicode map file — not achievable from a PDF alone in standard usage.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
