I have now fully read and analyzed all relevant code:

- `BuiltinFontTables.cc` (4285 lines, all static data tables + init/free at lines 4262–4285)
- `BuiltinFont.cc` (the actual `BuiltinFontWidths` class implementation)
- `BuiltinFont.h` (struct definitions)
- All callers of `getWidth` in Annot.cc, GfxFont.cc, SplashOutputDev.cc

**Analysis summary per group:**

**Group 1 (lines 1–4228): Static data tables**  
14 static arrays of `BuiltinFontWidth` structs with hardcoded glyph names and widths. Pure compile-time data. No code execution path, no memory operations. Clean.

**Group 2 (lines 4230–4285): builtinFonts, init/free**  
- `initBuiltinFontTables()`: passes hardcoded sizes (315, 316, 190, 202) to `BuiltinFontWidths` constructor. Actual table entry counts verified to match: all match exactly (helveticaBoldWidthsTab has 316, passed as 316, etc.).  
- `freeBuiltinFontTables()`: iterates `i` 0–13, deletes `builtinFonts[i].widths`. All 14 are allocated. Clean.

**Group 3 (BuiltinFont.cc): BuiltinFontWidths class**  
- Constructor: `gmallocn(size, sizeof(ptr))` with hardcoded positive sizes — no integer overflow possible. Iterates exactly `sizeA` entries, matching allocation.  
- `hash()`: `unsigned int h`, uses `h % size`; `size` is always positive, result always in `[0, size-1]`. `tab[h]` access always in-bounds.  
- `getWidth()`: All callers NULL-check the name pointer before passing it. No NULL dereference possible.

**Conclusion:** The file is entirely static lookup tables with a simple, correctly bounded hash table. No attacker-controlled data reaches any memory allocation size, no off-by-one exists, and all callers validate inputs properly.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
