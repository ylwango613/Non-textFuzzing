`Object::free()` correctly sets `type = objNone` at line 149, confirming the stream UAF path is safe. All analysis is complete.

**Batch 1 — `Lexer.cc` lines 1–200**: Number parsing: `xi` (int) can overflow on a very long digit sequence, but this is not a memory safety issue — it's just stored as an int object. Float parsing similarly benign.

**Batch 2 — String parsing (lines 225–340)**: The `tokBuf[128]` flush pattern is correct: when `n == tokBufSize`, the buffer is appended to GString and `p`/`n` are reset to 0 before the new character is written. No overflow.

**Batch 3 — Name parsing with goto (lines 343–406)**: At `n == tokBufSize` (128), `*p = (char)c` writes to `tokBuf[127]` (valid last slot), then GString is created with all 128 bytes. Beyond that, `s->append()` is always used — `p` is irrelevant and never advanced past 127. The `goto notEscChar` paths produce logic bugs (wrong character value written) but `n` is still correctly incremented once per iteration. No buffer overflow.

**Batch 4 — Hex string parsing (lines 417–477)**: The `++m == 2` gate before any buffer write, with the `n == tokBufSize` flush check, is correct. Illegal characters still increment `m` so they contribute to byte writes, but the buffer guard remains in place. `nErrors < 100` break is a DoS mitigation, not a safety hole.

**Batch 5 — Command parsing (lines 502–525)**: `++n == tokBufSize` triggers a break **before** writing the 128th character; null terminator is placed at `tokBuf[127]`. Array is never exceeded.

**Batch 6 — Stream lifecycle (`getChar()` and destructor)**: `Object::free()` sets `type = objNone` (line 149 of Object.cc), so `curStr.isNone()` correctly returns true after free. The while-loop exits cleanly when streams are exhausted. No UAF.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
