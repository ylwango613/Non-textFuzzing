Now let me analyze the complete picture from all the evidence gathered.

**Analysis Summary:**

**Array::add() (Array.cc:37-48):**
- `size` starts at 8, doubles via `size *= 2`. When `size` reaches `0x40000000` (1073741824), the next doubling is signed integer overflow (UB), producing `-2147483648` on x86.
- `greallocn(elems, -2147483648, sizeof(Object))` → hits `nObjs < 0` check → calls `gMemError` → aborts/throws. No heap corruption.
- Next doubling (if somehow bypassed) would give `size = 0` → `greallocn(0, ...)` → frees buffer, returns NULL → `elems[length] = *elem` is a NULL-write, but this path is unreachable because the prior step already aborts.
- Requires ~1 billion array elements, impractical in a real PDF.

**Array::get() / Array::getNF() (Array.cc:50-69):**
- Both properly check `i < 0 || i >= length` before accessing `elems[i]`. Bounds are correct.

**greallocn overflow check (gmem.cc:300):**
- `nObjs >= INT_MAX / objSize` check prevents product overflow in `n = nObjs * objSize`. The check ensures `(INT_MAX / objSize) * objSize ≤ INT_MAX`, so no integer overflow in the allocation size.

**Parser.cc array parsing loop (lines 59-67):**
- No limit on number of array elements parsed from a PDF, but memory exhaustion is handled by OS-level OOM, not heap corruption.

**Conclusion:** The `Array` class has correct bounds checking on all accessors, and `greallocn` has an overflow guard. The theoretical signed integer overflow in `size *= 2` is caught by greallocn's `nObjs < 0` check before any memory corruption occurs. No exploitable memory safety vulnerabilities exist in this code.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
