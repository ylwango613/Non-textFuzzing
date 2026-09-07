After reading all of GHash.h and GHash.cc in full, tracing the `expand()` / `hash()` / `add()` / `remove()` / iterator functions, and checking all GHash consumers in the xpdf codebase, here is my analysis:

**expand() integer overflow check:** `size = 2*size + 1` can theoretically overflow `int`, but `gmallocn` guards: `if (nObjs < 0 || nObjs >= INT_MAX / objSize)` — the check fires well before overflow (at size ≈ 268M, needing ~134M hash entries, far beyond any reachable PDF load and impossible to reach without first exhausting memory).

**hash() modulo safety:** `size` starts at 7 and only grows; division by zero is impossible. The `h % size` computation uses `unsigned int h` and `int size`, converting to unsigned — the result is always in `[0, size-1]`, a valid index.

**add() with duplicate keys:** Does not coalesce entries, but both objects are distinct allocations — no double-free or UAF on destruction.

**Iterator + concurrent modification:** UAF is theoretically possible if `remove()` is called while iterating, but this depends entirely on calling code patterns, not attacker-controlled PDF data.

**deleteGHash macro:** Correctly deletes values first, then `delete _hash` cleans up buckets and (if `deleteKeys`) key strings. No double-free.

**gmem.cc allocation guards:** `gmallocn`, `greallocn` all check `nObjs < 0` and `nObjs >= INT_MAX / objSize`, and `gmalloc` checks `size < 0`. No reachable path bypasses these guards in GHash.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
