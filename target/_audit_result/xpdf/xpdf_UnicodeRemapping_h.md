Completing the analysis with full context:

**Group 1 — `addRemapping()` (lines 81–107):**
- Grow condition `sMapLen == sMapSize` fires before `findSMap`, so the buffer is always large enough before memmove/write. `findSMap` returns `i ∈ [0, sMapLen]`; after grow, capacity is `sMapLen + 16`, so `sMap[i]` and `sMap[i+1..sMapLen]` are all within bounds. `++sMapLen` keeps `sMapLen ≤ sMapSize`. No OOB.

**Group 2 — `parseFile()` (lines 109–150):**
- `buf[256]` with `getLine(buf, sizeof(buf), f)` — bounded. `strlen(tok) ≤ 255`, cast to int is safe. All `out[n]` writes bounded by `n < maxUnicodeString (8)`. Crucially, `parseFile` reads from an **xpdfrc-specified config file**, not from the PDF byte stream — not directly attacker-controlled from a crafted PDF.

**Group 3 — `map()` (lines 170–201):**
- `size ≤ 0` check at top covers all `out[0]` writes. sMap binary search result `m ∈ [0, sMapLen)`. Inner copy `for (i = 0; i < sMap[m].len && i < size; ++)` is doubly bounded by `maxUnicodeString` and `size`. Fallthrough `out[0] = in; return 1;` also protected by the `size ≤ 0` guard.

**Caller in TextOutputDev.cc (line 1570):**
- `uBufSize` starts at 16; grow fires when remaining space `< 8` AND `uBufSize < 20000`. Since `maxUnicodeString = 8`, map() can never write more than 8 entries into a buffer that guaranteed at least 8 free slots. No overflow.

**`greallocn`:** Has explicit `nObjs >= INT_MAX / objSize` overflow guard before multiplication.

**Overall:** `UnicodeRemapping.h/cc` processes data from a trusted xpdfrc config file, not from the PDF input stream. The memory management is correct and all array accesses are in-bounds.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
