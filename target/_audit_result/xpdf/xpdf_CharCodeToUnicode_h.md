Having now completed a comprehensive multi-pass analysis of `CharCodeToUnicode.h` and `CharCodeToUnicode.cc`, let me summarize my findings across each function group:

**Group 1 (lines 1–225): Factory methods & file parsers**
- `parseCIDToUnicode` and `parseUnicodeToUnicode` read from config files (not PDF input) — not the primary attack vector.
- `parseUnicodeToUnicode`'s `size *= 2` loop could theoretically wrap to 0 for a huge `u0`, causing infinite loop — but only triggered from system config files, not a crafted PDF.

**Group 2 (lines 235–480): `parseCMap` / `parseCMap1` — PDF attack surface**
- In `beginbfchar`/`begincidchar`, the `code1 > maxCode` check emits a warning but does NOT skip the subsequent `addMapping`/`addMappingInt` call. However, both functions have their own `code > 0xffffff` guard, so out-of-range codes from a 16-bit CMap are handled safely.
- In `beginbfrange` (array form), `code1 + i` is unsigned; overflow wraps around but the `<= code2` comparison prevents spurious `addMapping` calls.
- `greallocn` takes `int nObjs`; the max possible `mapLen` from `addMapping` is `0x1000000` (16M), well within `INT_MAX`, so no signed integer overflow.
- The `usecmap` recursive call reads from system CMap files, not attacker-controlled data.

**Group 3 (lines 482–575): `addMapping` / `addMappingInt` / `parseUTF16String`**
- `parseUTF16String` bounds `uLen` via `if (uLen < maxUnicodeString)`, so the stack array `u[maxUnicodeString]` is never overflowed.
- `mapLen` growth is correctly bounded; `greallocn` has integer overflow checks (`nObjs >= INT_MAX / objSize`).
- `sMap` growth uses correct `sMapLen >= sMapSize` check before writing.

**Group 4 (lines 651–705): `setMapping` / `mapToUnicode`**
- `setMapping` writes `map[c]` without checking `c < mapLen`, but both callers supply `c < mapLen` by construction.
- `mapToUnicode` writes `u[0]` without checking `size >= 1`; all callers in Gfx.cc pass `sizeof(u)/sizeof(Unicode) = 8`.

**Group 5 (lines 707–763): `CharCodeToUnicodeCache`**
- Straightforward LRU cache; reference counting and cache shifting are correct.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
