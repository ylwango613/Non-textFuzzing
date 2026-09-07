After reading all 852 lines in two batches, the header, and gmem.h/gmem.cc, and cross-checking every notable caller of `del()`, `insert()`, and the 3-argument constructor, here is my complete analysis:

**Batch 1 (lines 1–200): Constructors, resize(), size()**
- `size()`: overflow guard `if (len > INT_MAX - delta)` is correct; `resize()` checks `length1 < 0`.
- 3-arg constructor `GString(GString*, int idx, int lengthA)`: no bounds check on `idx`, but both callers (AcroForm.cc:3000, Annot.cc:1158) only pass in-bounds indices derived from scanning `[0, str->getLength())`.

**Batch 2 (lines 200–572): appendfv(), format argument handling**
- Integer overflow on `idx` during format-index parsing could produce negative `idx` and OOB `args[idx]` read — but format strings are hardcoded source constants, not PDF data. Not externally triggerable.
- `fmtSpace` with large `arg.i` would loop many times appending spaces; each `append(' ')` checks `length > INT_MAX - 1` → `gMemError()` → `exit(1)`. No heap corruption.

**Batch 3 (lines 572–852): formatInt, formatDouble, insert, del, cmp**
- `formatDouble()`: guards `i > 1` on all write loops mean `i` cannot fall below 1 inside loops; the final `buf[--i]` for the `-` sign writes at worst `buf[0]`. No underflow.
- `del(int i, int n)`: if `i > length`, `n` becomes negative and `length` gets set to `i` (logical extension). The single-byte write `s[i] = s[length]` is within the physically allocated buffer as long as `i < size(length)`. All callers verify `i < length` before calling, so this edge case is unreachable in practice.
- `insert()` variants: no bounds check on `i`, but all callers pass in-bounds indices (0 or pointer arithmetic within the string).
- All `append()` variants have explicit `INT_MAX` overflow checks before `resize()`.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
