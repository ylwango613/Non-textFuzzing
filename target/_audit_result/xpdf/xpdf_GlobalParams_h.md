I've now read and analyzed the complete GlobalParams.h (648 lines) and GlobalParams.cc (4260 lines) in full.

**Analysis summary by section:**

**Config file parsing (`parseFile`, `parseLine`, `parseLineTokens`):**
- `buf[512]` in `parseFile()`, passed as `getLine(buf, sizeof(buf)-1, f)` — safe, at most 510 bytes read.
- `buf[256]` in `parseNameToUnicode()`, passed as `getLine(buf, sizeof(buf), f)` — safe, at most 255 bytes read.
- `sscanf(tok1, "%x", &u)` where `u` is `Unicode = unsigned int` — type matches `%x`, safe.
- GString token append in `parseLineTokens` variable expansion — dynamic growth, no fixed-size overflow.

**Font name munging (`mungeName1/2/3`, `match`):**
- `mungeName2`: pointer arithmetic with guards (`p2 - p0 >= 2/4` before any negative index access) — safe.
- `mungeName3`: `n >= 4/5/6/7` checked before `strcmp(nameA->getCString() + n - N, ...)` — safe.
- `match`: `strncasecmp(..., 2)` handles strings of any length — safe.

**Windows `scanWindowsFonts` (lines 511-518):**
- `n = strlen(data)`, then `strcasecmp(data + n - 4, ...)` with no guard on `n >= 4` — stack OOB read when `n < 4`. However: (1) Windows-only, (2) requires registry values with strings shorter than 4 characters (no realistic font name is that short), (3) **not triggered by a crafted PDF file** — only triggered during initialization from Windows registry.

**All accessor/setter functions:** Straightforward locking + field reads/writes, no memory safety issues.

**PDF attack surface via GlobalParams:** PDF content reaches GlobalParams only through font name lookups (`findFontFile`, `getCIDToUnicode`, etc.) which are safe hash table lookups.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
