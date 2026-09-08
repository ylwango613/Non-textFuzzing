Now I have read all 686 lines of PDFDoc.cc across 4 batches. Let me analyze each section:

**Batch 1 (lines 1-200) — Constructors:**
- `wchar_t` constructor (Win32): `n = fileNameLen < winMaxLongPath ? fileNameLen : winMaxLongPath; memcpy(wPath, fileNameA, n * sizeof(wchar_t)); wPath[n] = L'\0';` — clamped, safe.
- `readWindowsShortcut(wPath, ...)` can expand `wPath`. Subsequent loop `for (i = 0; i < wPathLen; ++i) { fileName->append((char)fileNameA[i]); }` uses `wPathLen = wcslen(wPath)` which may exceed `fileNameLen`. This is an OOB read of `fileNameA`. However, this is Windows-only and triggered by the file path argument, not PDF content — out of scope for the attack surface.

**Batch 2 (lines 200-399) — `checkHeader()`:**
- `char hdrBuf[1025]`, zeroed; `str->getBlock(hdrBuf, 1024)` fills at most 1024 bytes; loop bound `i < 1019`; `&hdrBuf[i+5]` at most `&hdrBuf[1023]`; null terminator from `memset`. Safe.

**Batch 3 (lines 399-600) — Setup, display, linearization, saveAs:**
- All stream reads use fixed stack buffers with sizes passed to `getBlock`. Safe if `getBlock` respects size. No direct PDF-controlled sizing of stack buffers.
- `isLinearized()` passes `&obj1` to `makeSubStream` then overwrites `obj1` via `getObj` — `makeSubStream` gets length=0 and `gFalse` (no limit); the dict parameter is incidental. No UAF.

**Batch 4 (lines 600-686) — `saveEmbeddedFile2`, `getEmbeddedFileMem`:**
- `saveEmbeddedFile2`: fixed `buf[4096]`, reads block-by-block — safe.
- `getEmbeddedFileMem`: `sizeInc = bufSize ? bufSize : 1024`; `if (bufSize > INT_MAX - sizeInc) return NULL` before `grealloc`; writes `n <= sizeInc` bytes at `buf + bufSize` into allocation of `bufSize + sizeInc` — safe. Memory leak of `buf` on overflow path is not a safety issue.

**Overall assessment:** PDFDoc.cc is high-level orchestration code. No malloc sizing from PDF-controlled integers, no OOB writes, no UAF patterns triggered by crafted PDF content.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
