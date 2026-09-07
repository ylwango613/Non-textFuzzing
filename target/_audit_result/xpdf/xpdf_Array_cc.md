Now I have the full picture. Let me complete the analysis.

**Array.cc — Full Analysis Summary:**

**Array::add() (lines 37-48):**
- `size` is `int`; `size *= 2` is signed integer overflow (UB) once `size` ≥ 2^30. However:
  - After overflow, `size` becomes negative → passed to `greallocn(elems, size, sizeof(Object))`
  - `greallocn` checks `nObjs < 0` → calls `gMemError`
  - `gMemError` either calls `exit(1)` or throws `GMemException` (no path back)
  - Execution never reaches `elems[length] = *elem` after the failed realloc
- Triggering the overflow requires ~2^30 (≈1 billion) elements in a PDF array — impractical
- The `greallocn` also checks `nObjs >= INT_MAX / objSize` for pre-overflow large values

**Array::get() / Array::getNF() (lines 50-70):**
- Both check `i < 0 || i >= length` before indexing `elems[i]` — correctly bounded

**Array::~Array() (lines 29-35):**
- Iterates `[0, length)` over `elems`, frees each, then `gfree(elems)` — correct

**Verdict:** No exploitable memory safety vulnerability exists in Array.cc. The `size *= 2` UB is theoretical and mitigated by `greallocn`'s checks; all array accesses are bounds-checked; destructor is correct.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
