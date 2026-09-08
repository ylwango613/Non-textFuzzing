Now I have all the context needed. Let me perform a thorough analysis of the code.

**Group 1 — Constructor / destructor / expand() (lines 21-171)**

- `TextString()`: zero-initializes, safe.
- `TextString(GString *s)`: calls `append(s)` → `insert(len=0, s)`. Safe path.
- `TextString(TextString *s)`: `gmallocn(size, sizeof(Unicode))` where size=s->len. The check inside `gmallocn` guards overflow (`nObjs >= INT_MAX/objSize`). Safe.
- `expand(int delta)`:
  - Overflow guard: `delta > INT_MAX - len` → sets `size=-1`, falls through to `greallocn(u,-1,4)` → `nObjs<0` → `gMemError` (throw/exit). Intentional, not exploitable.
  - Doubling path: `size > 0 && size <= INT_MAX/2 && size*2 >= newLen` — no overflow possible.
  - `greallocn` internal check: `nObjs >= INT_MAX / objSize` prevents overflow in `nObjs*objSize`. Safe.

**Group 2 — append/insert single Unicode (lines 46-67)**

- `append(Unicode c)`: calls `expand(1)` then writes `u[len]`. After expand, `size >= len+1`. Safe.
- `insert(int idx, Unicode c)`: same pattern; `memmove` and write are within bounds. Safe.

**Group 3 — insert(int idx, Unicode *u2, int n) (lines 69-79)**

```cpp
expand(n);
if (idx < len) memmove(u + idx + n, u + idx, (len - idx) * sizeof(Unicode));
memcpy(u + idx, u2, n * sizeof(Unicode));
len += n;
```

- No check that `n >= 0`. If n < 0: `expand(n)` computes `newLen = len+n` (may go negative), `n > INT_MAX-len` is false for negative n, `newLen <= size` is true if negative ≤ size → returns without realloc. Then `memmove(u+idx+n, ...)` with negative n → pointer before buffer start → OOB write. Then `memcpy(..., n * sizeof(Unicode))` where `n` (signed int negative) × `sizeof(Unicode)` (unsigned size_t) → integer promotion yields enormous size → catastrophic OOB write.
- **However**: all callers of this variant inside `insert(GString*)` use `n` accumulated from 0 upward and flushed at exactly 100. No external callers in the PDF parsing code pass attacker-controlled n to this overload. The public API risk exists but is not reachable from PDF input in the xpdf call chain.

**Group 4 — insert(int idx, GString *s) (lines 81-154)**

- BOM detection calls `s->getChar(0)`, `s->getChar(1)`, `s->getChar(2)` without length checks. For a zero-length GString: `getChar(0)` returns null-terminator (0x00) → BOM checks fail via short-circuit → PDFDocEncoding path with n=0, no loop. For length-1: same argument. GString always allocates length+1 bytes so reading the null terminator is in-bounds.
- `uBuf[100]` buffer: n cycles 0→99, write to `uBuf[n]`, then ++n, flush at n==100. Never exceeds uBuf[99]. Safe.
- `idx += n` accumulation: for extremely large strings, idx could overflow int, causing subsequent insert calls to fail the `idx>=0` check → no-op (characters lost, not memory corruption).
- PDFDocEncoding path: `pdfDocEncoding[s->getChar(i) & 0xff]` — 0xff mask guarantees index 0-255 into a 256-entry table. Safe.

**Group 5 — toPDFTextString / toUTF8 (lines 173-209)**

- Both iterate 0..len-1, operating only on already-populated `u[]`. No bounds issues.
- `mapUTF8` correctly bounds-checks before writing to `buf[8]`. Safe.

**Overall conclusion**: The code in TextString.h/TextString.cc is carefully written. The `expand()` overflow guard and `greallocn` checks cover all realistic input sizes. No reachable memory safety vulnerability exists through PDF-input-controlled call paths.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
