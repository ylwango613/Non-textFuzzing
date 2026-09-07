**Batch 1 analysis (lines 1-99):** Constructor initializes `size=7`, uses `gmallocn(7, sizeof(GHashBucket*))` — safe. `add()` calls `expand()` before inserting.

**Batch 2 analysis (lines 100-260):** `replace()`, `lookup()`, `remove()` — standard linked-list traversal via `find()`. `remove()` correctly unlinks the bucket before `delete p`. No double-free or UAF.

**Batch 3 analysis (lines 261-334):** `getNext()` starts iterator at `h=-1`, increments before use, terminates when `h == size`. `tab[(*iter)->h]` is only accessed after the `== size` check. `expand()` does `size = 2*size+1` (signed `int`) — theoretical overflow after ~29 doublings (~2^29 entries), but `gmallocn` catches negative `nObjs` with `gMemError`→`exit(1)`, making it a DoS-only condition requiring billions of entries — unreachable from any realistic PDF.

**Batch 4 analysis (lines 336-381):** `hash(GString*)` returns `(int)(h % size)` — `h` is `unsigned int`, `size` is always ≥7 in normal operation. `hash(const char*)` is equivalent. Both correct modulo arithmetic.

**gmallocn overflow guard** (gmem.cc:210): `if (objSize <= 0 || nObjs < 0 || nObjs >= INT_MAX / objSize)` → guards all allocations in GHash against overflow.

**Attacker control surface**: GHash keys come from PDF name/string objects. An attacker can supply arbitrary keys, but the hash computation and bucket operations have no OOB path reachable with a finite, practical number of entries.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
