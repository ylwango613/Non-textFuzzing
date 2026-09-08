After completing my analysis, let me verify one last thing — the `readStringTag` integer overflow path on 32-bit systems and whether `readOrThrow` reliably catches it.

The analysis covers:

1. **`readStringWcharTag` — `FieldBuf.end() - 3`**: `DataBuf` has `length + 1` bytes; `enforce(length >= 2)` guarantees `size >= 3`, so `end() - 3 >= begin()`. **Safe.**

2. **Unsigned underflow `io->size() - io->tell()`** in all enforce checks (CWE-191, latent): If `io->tell() > io->size()`, the subtraction wraps to a large value making the bounds check pass. However, the subsequent `io->readOrThrow(buf, length, err)` calls `enforce(nread == rcount, err)` — when the position is beyond EOF the underlying `read()` returns 0 bytes and this secondary enforce unconditionally throws. Similarly, `io->read(DWORD)` can return a short DataBuf, causing `FieldBuf.read_uint32(0, ...)` to throw `std::out_of_range`. The double guard prevents exploitation.

3. **`DataBuf(length + 1)` integer overflow on 32-bit** (CWE-190): If `length = SIZE_MAX = UINT32_MAX` (32-bit), `length + 1 = 0`, creating an empty `DataBuf`. `readOrThrow(empty.data(), SIZE_MAX, ...)` → `fread` at beyond-EOF returns 0 → enforce throws. Not exploitable.

4. **`readStringWcharTag` double charset conversion**: logical bug (unconditional `convertStringCharset` at line 47 always runs, plus conditional call at line 46 for odd sizes), not a memory safety issue.

5. **Large `length` allocation DoS** (up to 4GB on 64-bit from attacker-controlled DWORD): DoS from `std::bad_alloc`, not memory corruption.

6. **`string_from_unterminated`**: safe — `strnlen` bounds-respects `data_length`, and callers in context hold DataBuf with validated sizes.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
