Having completed the full analysis:

**Group 1 — `mapUTF8` / `mapUCS2` (lines 12–58):** Both functions guard every write branch with `if (bufSize < N) return 0` before writing. All callers pass fixed-size stack buffers (8 bytes, 4 bytes, etc.) that exceed the maximum encoding length. No OOB.

**Group 2 — `getUTF8` (lines 61–139):** Each multi-byte branch (`c0 < 0xe0 … c0 < 0xfe`) uses signed integer comparisons: `*i < s->getLength() - K`. Because `getLength()` returns `int`, small lengths produce negative right-hand sides, and since `*i` starts non-negative, the checks evaluate to false—correctly rejecting reads past the end. `GString::getChar(i)` has no bounds check (`return s[i]`), but every call is guarded by a prior length comparison. No OOB.

**Group 3 — `getUTF16BE` / `getUTF16LE` (lines 141–183):** Initial guard `*i >= s->getLength() - 1` correctly ensures 2 bytes are available. Surrogate-pair read is guarded by the same pattern. Arithmetic on `w0` and `w1` stays within `unsigned int` range. No OOB.

**Callers — TextString.cc BOM detection (lines 87–125):** `getChar(0/1/2)` accesses without length checks, but `GString` always null-terminates (constructor: `s[0] = '\0'`, every resize keeps a terminator), so even a 0-length string keeps a valid byte at `s[0]`. Combined with `&&` short-circuit, these accesses never reach unallocated memory.

**Callers — AcroForm.cc `utf8ToUnicode` (lines 3191–3205):** The two-pass pattern is safe: `gmallocn(0,…)` returns NULL, but for an empty string the second `getUTF8` loop exits before writing to `uVec[0]`.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
