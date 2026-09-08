After reading the complete file in full and verifying all key paths:

**Analysis summary:**

1. **`readRawProfile` `unhex` access (lines 556-571)**: The filter `while` loop guarantees `*sp` exits only when `*sp` is in `['0'-'9']` (48–57) or `['a'-'f']` (97–102). Both ranges are within `unhex[103]` (indices 0–102). On signed-char platforms, negative bytes satisfy `*sp < '0'` → filtered. Values 103–127 satisfy `*sp > 'f'` → filtered. No OOB.

2. **Length parsing overflow (lines 516–525)**: No overflow check on `10 * length + digit`. However, both `info.alloc(length)` and `nibbles = length * 2` use the same (possibly wrapped) `length`, so the write loop and the buffer stay in sync. The `enforce(length <= (eot - sp) / 2)` at line 531 uses the *actual* remaining text, bounding any real OOB scenario.

3. **iTXt offset arithmetic (lines 141–154)**: All critical additions use `Safe::add`; the only raw arithmetic is `keysize + 3 + languageTextSize + 1`, which is bounded by `data.size()` (≤ 2^31−1 on PNG), safe on 64-bit.

4. **`zlibUncompress` (lines 336–364)**: DoS cap at 131072 bytes; the `dos > 1` guard limits iterations to three at most.

5. **IPTC `pEnd` (line 236)**: `psData.empty()` guard precedes, so `psData.size() - 1` cannot underflow.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
