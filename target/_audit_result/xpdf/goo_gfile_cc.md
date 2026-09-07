I've now read all 802 lines of `gfile.cc` in three batches (lines 1–400, 400–802) plus the complete GString implementation. Let me do final cross-checks on the most interesting patterns before concluding.

**Batch 1 (lines 1–400) findings:**
- `appendToPath` Win32: `char buf[256]`, but `GetFullPathNameA(…, sizeof(buf), …)` passes the exact limit — no stack overflow.
- `makePathAbsolute` Unix: `strncpy(buf, p1, n)` with `n = min(p2-p1, PATH_MAX)`, then `buf[n] = '\0'` — correct.
- `makePathAbsolute` raw pointer `p1` used for arithmetic only after `path->del`/`path->insert` calls — no dangling dereference.

**Batch 2 (lines 400–802) findings:**
- `openTempFile` Unix: `mkstemps((*name)->getCString(), strlen(ext))` modifies GString's internal buffer in-place — intentional and safe (length doesn't change, XXXXXX→random 6 chars, GString `length` field stays correct).
- `getLine`: loop `while (i < size-1)` with all callers passing `sizeof(buf)` (compile-time constant > 1). Maximum write is `buf[size-1]` for the null terminator — correct.
- `fileNameToUCS2` (Win32): loop `i < outSize - 1` with all callers passing `winMaxLongPath + 1 = 32768` — safe. Three-byte UTF-8 branch reads `p[1]`/`p[2]` but short-circuits safely via C's `&&` evaluation when `p[1]` or `p[2]` is null.

**GString internal check:**
- `resize()` checks `length1 < 0` and uses `size()` which checks `len > INT_MAX - delta`.
- All `append`, `insert`, `del` operations guard against integer overflow with `INT_MAX` checks before arithmetic.
- `GString::insert(int i, const char *str)`: loop writes `s[length+n]` = old null terminator, correctly becomes new null terminator.

**Attack-surface assessment for pdftotext (crafted PDF → gfile.cc):**
- `getLine` in gfile.cc reads from `FILE *` config files, not PDF stream data.
- `openTempFile` is called from `SplashFTFontEngine.cc` for font temp files, but the function itself is safe.
- `appendToPath` is called with PDF-embedded filenames only in Qt viewer code (`QtPDFCore.cc`), not `pdftotext`.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
