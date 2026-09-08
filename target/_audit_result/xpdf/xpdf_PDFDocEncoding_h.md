After thorough analysis of `PDFDocEncoding.h`, `PDFDocEncoding.cc`, `TextString.cc` (primary consumer), `UTF8.cc`, `GString.cc`, and `gmem.cc`, the findings are:

**PDFDocEncoding table access** (`TextString.cc:148`): `pdfDocEncoding[s->getChar(i) & 0xff]` — the `& 0xff` mask guarantees index is always in [0, 255]. Safe.

**BOM checks without length guard** (`TextString.cc:87-125`): Accesses `s->getChar(0)`, `getChar(1)`, `getChar(2)` without checking `getLength()`. However, `GString::size()` always allocates at least 8 bytes (`size(0) = 8`, `size(1) = 8`, etc.), so `s[0..7]` is always within the allocated buffer regardless of logical length. Not exploitable OOB.

**`TextString::expand(delta)`** (`TextString.cc:156-171`): Checks `delta > INT_MAX - len` before computing `newLen` (note: `newLen = len + delta` is computed first with potential signed overflow, technically UB, but `greallocn` with `size=-1` aborts cleanly). In practice no exploitable path.

**uBuf[100] stack buffer** (lines 82, 91-97, 110-116, 128-133): Loop invariant ensures n is [0..99] when `getUTF16BE/LE/getUTF8` writes to `uBuf+n`. Flushed before overflow. Safe.

**`greallocn`/`gmallocn`**: Both check `nObjs < 0 || nObjs >= INT_MAX / objSize` and abort on invalid sizes. No allocation confusion.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
