**Analysis summary of FixedPoint.h + FixedPoint.cc:**

- **Constructors (lines 31–36):** All operate on `int val` with no allocation. `FixedPoint(Guint x)` and `FixedPoint(long x)` have potential signed-integer UB on shift, but produce no memory corruption.
- **Arithmetic operators (+, -, *, /, +=, etc.):** Delegate to `mul()`/`div()` helpers or direct `val` arithmetic. No buffer or pointer operations anywhere.
- **`mul()` (line 79):** Uses 64-bit intermediate with saturation clamping — no overflow path.
- **`div()` (line 92):** Division by zero if `y==0` → SIGFPE crash (DoS), but no memory write/read out-of-bounds.
- **`divCheck()` (line 105):** Same div-by-zero risk on `y.val==0`, but same characterization — process crash only.
- **`pow()` (line 36):** `z.val <<= n` (line 71) is undefined behavior when `n >= 32`; `z.val >>= -n` (line 73) is UB when `-n >= 32`. These are signed-integer shift UBs that produce incorrect arithmetic values but do not corrupt memory buffers, heap, or stack.
- **`sqrt()`, `avg()`, `floor()`, `ceil()`, `round()`, `checkDet()`:** Pure arithmetic, no memory operations.

The file contains **no memory allocation, no array indexing, no pointer arithmetic, no heap/stack buffer operations**. The identified issues (division by zero → SIGFPE crash; shift UB in `pow`) are either DoS-only or arithmetic UB — neither constitutes a memory safety vulnerability (OOB write/read, heap overflow, UAF, integer overflow into a dangerous allocation).

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
