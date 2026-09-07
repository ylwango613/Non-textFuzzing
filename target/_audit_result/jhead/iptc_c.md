Now I have complete context. Let me trace all critical paths thoroughly before finalizing.

**`show_IPTC` analysis — complete trace:**

**Lines 58–59:** `pos = Data + 2`, `maxpos = Data + itemlen`. Guard at line 63 ensures `itemlen >= 25`, so `pos + 23 <= maxpos`. Safe start.

**While loop (lines 73–91) — bounds invariant tracking:**
- First iteration: `pos = Data+19`, `maxpos >= Data+25`. `pos+2 <= maxpos` → `memcmp` safe; `*pos` (line 76) safe since `pos < maxpos`.
- After each iteration: line 82 establishes `pos+16 <= maxpos`, line 90 advances by 3 → `pos+13 <= maxpos`. The while-condition `memcmp(pos, 2)` is safe. `*pos` (line 76) after advancing +2 gives `pos+11 <= maxpos` → `pos < maxpos`. Invariant maintained.

**Lines 93–108:** After while exits: `pos+13 <= maxpos`. `pos += 2` → `pos+11 <= maxpos`. Guard `pos+16 >= maxpos` at line 95. After passing: `*pos++` (line 100) safe; `pos += headerLen + 1 - (headerLen%2)` can be up to +255, then caught by `pos+8 >= maxpos` at line 103.

**Main IPTC loop (lines 113–177):**
- `length` is `short` (signed). Value computed from 2 unsigned bytes: if > 32767, wraps negative (implementation-defined). `if (length < 1) goto corrupt;` catches both 0 and negative values.
- `if (pos+length > maxpos) goto corrupt;` — at this point `length >= 1`, so pointer arithmetic is safe.
- `printf("%s %*.*s\n", TempBuf, length, length, pos)` — `length` in `[1,32767]`, promoted to `int` for variadic; precision limits read to `length` bytes from `pos`, which is bounded by the prior check.

**TempBuf (lines 170–174):**
- `description` is **always a compile-time constant string** — not attacker-controlled. The longest value is `"OriginalTransmissionReference"` (29 chars + ":" = 30), which fits in `TempBuf[32]`. No overflow.

**`ShowXmp` analysis:**
- `OutLine[101]`. `OutLineChars` starts at 0. Writing advances it to max 100, then flush writes null at `OutLine[100]` and resets to 0. Index 100 is valid (array size 101). No overflow path.

After exhaustive analysis, all bounds checks in `iptc.c` are adequate, `description` is never attacker-controlled, signed `length` truncation is caught before pointer arithmetic, and `ShowXmp` correctly bounds its stack buffer.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
