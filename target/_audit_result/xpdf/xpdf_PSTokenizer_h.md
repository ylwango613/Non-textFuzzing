**Analysis summary:**

**PSTokenizer::getToken (PSTokenizer.cc, lines 50–114):**
- Line 76: `buf[i++] = (char)c;` is unconditional (no size check), but i=0 here, writing buf[0]. Theoretical OOB only if size=0; all callers pass `sizeof(tok)=256`.
- Lines 80, 95, 105: loop writes are guarded by `if (i < size - 1)` — maximum loop index is `size-2`.
- Line 110: null terminator `buf[i]='\0'` where i ≤ size-1. Safe.

**specialChars[] indexing:**
- Line 69: c checked for EOF at line 58 first; c is a byte (0–255) when accessed. Safe.
- Lines 95, 103: c from lookChar() checked `!= EOF` in while condition. Safe.

**Callers (CMap.cc:157, CharCodeToUnicode.cc:260):**
- Both use `char tok[256]` + `pst->getToken(tok, sizeof(tok), &n)` — size always 256. No overflow.

**Downstream addMapping calls:**
- `addMapping(code1, tok2+1, n2-2, 0)`: n2 ≥ 1 (getToken always writes ≥1 char), so n2-2 ≥ −1. `parseUTF16String` with n≤0 exits the while loop immediately (returns 0), causing early return. Safe.
- `tok1[n1-1]` indexing: n1 ≥ 1 guaranteed by getToken semantics. Safe.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
