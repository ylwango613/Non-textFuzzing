Now I have all the context needed. Let me analyze carefully:

**`NameToCharCode.cc` analysis:**

1. **Constructor** (line 25-34): `gmallocn(31, sizeof(NameToCharCodeEntry))` — `gmallocn` checks for overflow, initial size fixed at 31. No issue.

2. **`add()` — len double-count bug** (line 86): `++len` is unconditional. If the same key is inserted twice, `len` increments but the slot count doesn't grow. This inflates `len` and triggers rehash prematurely, but the table never overfills because growth always precedes insertion. No OOB.

3. **`add()` — growth loop** (lines 62-68): rehash iterates `oldSize` entries into a new table of `size = 2*oldSize+1`. Linear probe with wrap-around. Since the new table is more than double the old, all entries fit. No OOB.

4. **`add()` — insertion probe** (lines 76-80): linear probe until NULL or matching key. Since growth ensures at most `size/2` entries exist in a table of `size` slots (accounting for `len` overcount still bounded by growth triggers), the probe always terminates. No infinite loop reachable from crafted PDF input.

5. **`lookup()` — probe loop** (lines 93-99): same linear probe terminating at NULL. Table never fully populated for same reasons above.

6. **`hash()`** (lines 104-113): `unsigned int h` modulo `size` (positive int). Return value always in `[0, size-1]`. No negative index.

7. **`gmallocn` sizes**: grow as 31→63→127→… never approaching `INT_MAX`. No integer overflow in allocation sizes.

8. **External input path**: `nameToUnicode` is populated from hard-coded tables (`nameToUnicodeTab`) and optionally from xpdf config files — not directly from crafted PDF content via `pdftotext`. `macRomanReverseMap` is populated from the hard-coded `macRomanEncoding` array (256 fixed entries). Neither path exposes attacker-controlled keys/values through a crafted PDF file alone.

No exploitable memory safety vulnerability found in this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
