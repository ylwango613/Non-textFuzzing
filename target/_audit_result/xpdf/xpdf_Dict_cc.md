All 142 lines of Dict.cc read. Callers verified in Page.cc and GfxFont.cc. Memory allocators confirmed in gmem.cc. Analysis complete.

**Group 1 (lines 1–86): Constructor, destructor, add, expand**
- `gmallocn`/`greallocn` both validate `nObjs >= INT_MAX / objSize` before multiplying, so no integer-overflow-to-small-alloc.
- `size *= 2` could cause signed int overflow (UB) when size reaches `INT_MAX/2`, but the immediately following `greallocn` call with the overflowed (negative) size triggers `gMemError` and exits — no heap corruption reachable.
- After `greallocn(entries, ...)`, `expand()` does `memset(hashTab, 0, ...)` then rebuilds all `hashTab[h]` and `->next` pointers from the fresh entries array. No stale pointer is ever dereferenced.

**Group 2 (lines 88–110): find, hash**
- `hash` returns `h % (2 * size - 1)` where `h` is `unsigned int` and the result is cast to `int`. The modulus is always positive while size is valid, so the return value is always within `[0, 2*size-2]` — a valid hashTab index.
- `find` walks the `->next` chain; all `next` pointers are rebuilt in `expand()` before any subsequent use.

**Group 3 (lines 112–141): is, lookup, lookupNF, getKey, getVal, getValNF**
- `getKey(i)`, `getVal(i, obj)`, `getValNF(i, obj)` perform no bounds check on `i`, but every call site (Page.cc:142-169, GfxFont.cc:2436-2439, PSOutputDev.cc:3294-3296) uses `getLength()` as the exclusive loop bound, providing correct external guards.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
