Based on the complete analysis of GList.cc and its context, let me document what I found:

**Group 1 – Constructor/destructor (lines 21–37):** `GList()` initializes `size=8`, allocates via `gmallocn`. `GList(int sizeA)` passes `sizeA` to `gmallocn` which validates `nObjs < 0`. No issues.

**Group 2 – `copy()` (lines 39–47):** `new GList(length)` → allocates exactly `length` slots; `memcpy` copies exactly `length * sizeof(void*)` bytes. Sizes match. `length * sizeof(void*)` is `int * size_t` → promotes safely. If `length < 0`, `gmallocn` aborts before `memcpy` runs.

**Group 3 – `append(void*)` / `append(GList*)` (lines 49–65):** Single-element append correctly calls `expand()` before write. The `append(GList*)` while-loop guards the write. Integer overflow of `length + list->length` is theoretically possible but requires billions of elements (>8 GB) — not practically reachable from a PDF file.

**Group 4 – `insert()` (lines 67–79):** Clamps `i < 0` → 0, but does **not** clamp `i > length`. If `i >= size`, `data[i] = p` is a heap OOB write. However, examining all callers: TextOutputDev.cc uses indices bounded by `getLength()` (search loops that stop at list length), and other callers pass constant `0`. No PDF-derived unchecked index is passed to `insert()`.

**Group 5 – `del()` (lines 81–93):** No bounds check on `i` at all — `data[i]` is unchecked. All callers (JBIG2Stream.cc, TileCache.cc, TextOutputDev.cc) compute indices against `getLength()` before calling.

**Group 6 – `expand()` / `shrink()` (lines 116–124):** `size += size` could overflow, but `greallocn` catches `nObjs < 0`. `size -= inc` with `inc > size` underflows, but again caught by `greallocn`. No exploitable path.

**gmallocn/greallocn safety net:** Both check `nObjs < 0` and `nObjs >= INT_MAX / objSize`, providing robust protection against size-overflow allocations.

**Callers cross-check:** All `->insert(i, …)` and `->del(i)` callers I traced compute `i` within `[0, getLength()]` before the call, respecting the preconditions documented in GList.h.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
