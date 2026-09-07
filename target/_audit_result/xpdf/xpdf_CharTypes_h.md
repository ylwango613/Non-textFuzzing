The file `CharTypes.h` is 24 lines containing only three `typedef unsigned int` declarations. After examining related usage in `CharCodeToUnicode.cc` and `GfxFont.cc`:

- `setMapping()` lacks a bounds check, but both callers constrain `c` within `mapLen` range.
- Fixed-size 256-element arrays (`enc[]`, `toUnicode[]`, `widths[]`) are all accessed with `code` after explicit `code >= 0 && code < 256` guards or `for (code = 0; code < 256; ++code)` loops.
- `addMapping()` / `addMappingInt()` guard `code > 0xffffff` and grow `map` dynamically before indexing.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
