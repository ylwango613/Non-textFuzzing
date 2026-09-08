Now I have sufficient context. Let me complete my analysis.

**Analysis summary for TextString.cc:**

**`expand(int delta)` (lines 156-171):**
- Integer overflow check: `delta > INT_MAX - len` → sets `size = -1` → `greallocn(u, -1, sizeof(Unicode))` → `gMemError` (throws `GMemException` or calls `exit(1)`). Not exploitable.
- Double-growth logic with `INT_MAX/2` guard is correct.

**`insert(int idx, GString *s)` BOM parsing loops (lines 81-154):**
- `uBuf[100]` stack buffer: the flush check `n == sizeof(uBuf)/sizeof(Unicode)` (= 100) fires *after* `++n`, so valid write indices are `[0..99]`. No stack overflow.
- `getUTF16BE/LE` boundary check `*i >= s->getLength() - 1` is correct for any non-negative length.
- BOM detection `getChar(0)`, `getChar(1)`, `getChar(2)` on short strings: short-circuit evaluation + GString's null terminator make these reads land within allocated memory (at worst reading the NUL byte).

**PDFDocEncoding branch (lines 141-151):**
- `n = s->getLength()`, `expand(n)`, then `memmove` + loop. Buffer is sized to `len + n`, writes are to `u[idx .. idx+n-1]` where `idx <= len`, so the last write is at `idx + n - 1 <= len + n - 1 < size`. Correct.

**`insert(int idx, Unicode *u2, int n)` (lines 69-79):**
- `expand(n)` → buffer has `>= len + n` elements.
- `memmove` destination `u + idx + n` through `u + len + n - 1` → within bounds.
- `memcpy` destination `u + idx` through `u + idx + n - 1 <= u + len + n - 1` → within bounds.

**Copy constructor (lines 32-40):**
- `gmallocn(size, sizeof(Unicode))` with overflow check → safe.

No memory safety vulnerabilities found in this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
