I now have a complete picture of the code. Let me analyze all findings:

**Group 1 — `BuiltinFontTables.h` (lines 1-23):** Pure header with `#define` constants (`nBuiltinFonts=14`, `nBuiltinFontSubsts=12`) and extern array/function declarations. No executable code here.

**Group 2 — `BuiltinFont.cc` — hash table construction and lookup:**
- Constructor `BuiltinFontWidths(widths, sizeA)`: allocates `tab[sizeA]` and iterates `sizeA` times. Hash is computed as `h % size`; since `size = sizeA`, index is always in `[0, sizeA-1]`. Compile-time constants drive `sizeA`, so no external input controls this.
- `hash(name)`: returns `(int)(h % size)`. If attacker passes any name, the result is always in range `[0, size-1]` (size is a fixed positive integer set at construction time). Correct.
- `getWidth(name, &w)`: all callers either NULL-check `name` before calling (`enc[code] && ...`, `charName && ...`, SplashOutputDev's `(name = ...) && name[0] && ...`), or pass a string literal. No NULL dereference path.

**Group 3 — `BuiltinFontTables.cc` — font table usage:**
- `builtinFonts[]` has 14 compile-time entries; `initBuiltinFontTables()` initializes indices 0-13; `freeBuiltinFontTables()` loops `i < 14`. No mismatch.
- `builtinFontSubst[]` has 12 compile-time entries (indices 0-11). The only unchecked indexing is in `GfxFont.cc:1446`: `i` starts at 0/4/8 and adds at most 2+1=3, giving maximum values of 3/7/11 — all within [0,11]. Correct.
- `SplashOutputDev.cc:1678` has an explicit bounds check: `substIdx >= 0 && substIdx < 12` before accessing `builtinFontSubst[substIdx]`. Correct.

**Conclusion:** The entire code path in `BuiltinFontTables.h` and its associated implementation files operates exclusively on compile-time static data. The only external input (glyph names from PDF encodings) reaches `getWidth()` where it is either NULL-guarded by callers or correctly bounded by the hash `% size` modulus. No memory safety vulnerabilities are present.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
