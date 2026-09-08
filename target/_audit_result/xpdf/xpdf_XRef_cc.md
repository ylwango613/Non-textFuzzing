I've now read all 1457 lines of XRef.cc across four batches and traced into `gmem.cc` for the allocator internals. Let me consolidate my findings per section:

**Batch 1 (1–500):** `XRefPosSet::add` has an explicit `size > INT_MAX/2` guard before doubling; `ObjectStream` constructor bounds `nObjects` to 1,000,000 and checks `offsets[i] >= 0` and non-decreasing; offset `discardChars(offsets[0])` can be at most INT_MAX (no corruption, just slow).

**Batch 2 (500–867):** `readXRefTable` parses `first` and `n` with per-digit overflow guards (`first > (INT_MAX - digit) / 10`) and an additive overflow check (`first > INT_MAX - n`). The array resize loop has an `INT_MAX/2` guard. `readXRefStream` allocates entries to `/Size` (int, checked `< 0`) via `greallocn`, which internally checks `nObjs >= INT_MAX / objSize`. `readXRefStreamSection` checks `first + n < 0` for signed-wrap and `newSize < 0` after left-shifting.

**Batch 3 (868–1142):** `constructXRef` buffer scanning uses a null-terminated 4097-byte buffer; parsing loops stop at `'\0'`. `constructObjectEntry` limits `num` to ~10^9 via the `num < 100000000` do-while condition. `constructXRefEntry` computes `newSize = (num + 1 + 255) & ~255` and checks `newSize < 0`. Even with `num ≈ 10^9`, the subsequent `greallocn(entries, ~10^9, 16)` triggers `gMemError` (exit) because `10^9 > INT_MAX/16 = 134217727`.

**Batch 4 (1142–1457):** `fetch()` gates compressed-entry access with `e->offset >= (GFileOffset)size` before indexing `entries[e->offset]`. Since compressed entries are set only via `readXRefStreamSection` (which validates `offset >= 0`) or `constructXRefEntry` (with a valid object number), no negative-offset OOB access is possible. `getObjectStreamFromCache` and `addObjectStreamToCache` are bounded by `objStrCacheSize = 128`. `getStartXref` properly null-terminates its 1025-byte buffer.

**Potential false candidates that don't hold up:**
- `gen` int overflow in `readXRefTable`: UB but consequence is only a generation-mismatch error in `fetch()`; no memory is indexed by gen.
- `off` (GFileOffset) no overflow check in xref offset parsing: only used for file seeking, not as array index.
- Large `/Size` → `greallocn`: blocked by `nObjs >= INT_MAX / objSize` check.

After exhaustive analysis of all code paths, bounds checks, and allocator guards in XRef.cc, no exploitable memory safety vulnerability is present.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
