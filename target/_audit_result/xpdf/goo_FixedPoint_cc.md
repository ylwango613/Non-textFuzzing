Now I have the full picture. Let me perform a thorough analysis of every function in `FixedPoint.cc` and the supporting header.

---

**Group 1 — `sqrt()` (lines 20-34)**
- All arithmetic on stack `int` values (`y0.val`, `y1.val`, `z.val`)
- No heap allocation, no array indexing, no pointer arithmetic
- `x.val <= 0` guard prevents degenerate inputs
- Newton-Raphson loop converges; early termination is integer-diff based
- **No memory-safety issue**

**Group 2 — `pow()` (lines 36-77)**
- `n = floor(t / ln2)` yields a signed `int` derived from external data
- Line 71: `z.val <<= n;` — if `n >= 32`, this is C++ UB (shift ≥ type width)
- Line 73: `z.val >>= -n;` — same UB if `-n >= 32`
- However: `z.val` is a stack-local `int`; the result is never used as a malloc size, array index, or pointer offset in this file. On x86, the CPU takes `n % 32`, so the value wraps; no memory is addressed. Pure arithmetic UB, not a memory-safety reachable exploit primitive.
- `d *= i` can overflow `int` but the loop guard `d < (1 << fixptShift)` limits iterations; again all on stack, no memory effects.
- **No memory-safety issue**

**Group 3 — `mul()` (lines 79-90)**
- Widens to `FixPtInt64` (64-bit), then saturates back to `int`; correctly handles overflow
- **No memory-safety issue**

**Group 4 — `div()` (lines 92-103)**
- `z = ((FixPtInt64)x << fixptShift) / y;` — division by zero if `y == 0` → SIGFPE
- Callers in the header (`operator/`, `operator/=`) do not check for zero denominator
- This can cause a crash (DoS), but it is **not a memory-safety vulnerability**; no heap memory is touched

**Group 5 — `divCheck()` (lines 105-115)**
- Same potential division by zero on `y.val == 0` before any overflow check
- Still a crash/DoS, not memory corruption
- **No memory-safety issue**

**Group 6 — `checkDet()` (lines 117-128)**
- Only 64-bit multiply and compare; fully saturated; no allocation
- **No memory-safety issue**

**Header analysis (`FixedPoint.h`)**
- `FixedPoint(Guint x) { val = x << fixptShift; }` — if `x > INT_MAX >> 16`, `x << 16` overflows `int` (UB), but `val` is a stack field, never used as a size/index
- All operators delegate to `mul()`/`div()` which are bounded; `make()` writes only to a local stack object
- **No memory-safety issue**

**Summary:** `FixedPoint.cc` is a 131-line pure-arithmetic fixed-point library. It contains zero heap allocations, zero array accesses, and zero pointer arithmetic. No value computed here flows into a `malloc` size parameter, array subscript, or pointer offset without passing through well-checked higher layers. The only technical issues (div-by-zero, UB shifts) are DoS-class or arithmetic UB — neither qualifies as a memory-safety vulnerability under the audit scope.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
