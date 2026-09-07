After thorough analysis of `gmem.h`, `gmem.cc`, `GString.cc`, and `GList.cc`, I've completed the audit. Here is my assessment:

**Key findings from analysis:**

1. **`gmallocn`/`greallocn` overflow checks** (gmem.cc:210, 300): The condition `nObjs >= INT_MAX / objSize` uses short-circuit evaluation — `objSize <= 0` fires before the division, preventing divide-by-zero. The check is conservative but correct.

2. **`gmallocn64` missing `objSize==0` check** (gmem.cc:284): `(size_t)nObjs >= SIZE_MAX / objSize` would cause divide-by-zero UB if `objSize==0`. This is a DoS/crash, NOT a heap overflow, and is outside the pdftotext attack surface (callers are in Splash.cc rendering).

3. **`copyString` int truncation** (gmem.cc:393): `(int)strlen(s) + 1` could overflow for strings >2GB, causing under-allocation and `strcpy` overflow. Requires 2GB+ string input — impractical for a PDF.

4. **`GString::append` operations** (GString.cc:215-256): All properly check `length > INT_MAX - n` before resize/memcpy.

5. **`GList::expand()`** (GList.cc:116-118): `size += size` could cause signed int overflow UB at ~2^30 entries (8 GB pointer array — impractical), then `greallocn` catches the negative value.

6. **`gmalloc(int size)` / `grealloc(void*, int size)`**: Properly reject `size < 0`.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
