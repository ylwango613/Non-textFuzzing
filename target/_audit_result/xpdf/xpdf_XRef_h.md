Based on my thorough analysis of the full XRef.h and XRef.cc (1457 lines, read in four batches), and verification of the gmem.cc helper functions, here are the key findings:

**Allocation sites**: All `greallocn`/`gmallocn` calls have the overflow guard `nObjs >= INT_MAX / objSize` → `gMemError` (abort, not heap corruption). For `sizeof(XRefEntry) ≈ 16`, the threshold is ~134M objects — any larger request aborts cleanly.

**Array accesses** (`entries[i]`): In `fetch()` (line 1201), bounds are checked (`num < 0 || num >= size`) before `entries[num]`. In `readXRefTable` and `readXRefStreamSection`, `entries` is reallocated to `>= first+n` before the index loop runs.

**Integer overflow paths in `readXRefTable`** (lines 536-570): `first` and `n` both have explicit `(INT_MAX - digit)/10` parsing guards; `first + n` has a pre-allocation overflow check (`first > INT_MAX - n`); the doubling loop has `newSize > INT_MAX/2` → err1.

**`readXRefStreamSection`** (line 792): The `first + n < 0` check is technically signed-integer-overflow UB (compiler may remove it), but even if removed, the doubling loop `for (newSize = ...; first+n > newSize && newSize > 0; newSize <<= 1)` terminates with `newSize < 0` and returns gFalse before any corrupting access. The for-loop body `entries[i]` is never reached out-of-bounds.

**`constructXRefEntry`** (line 1118): `num` is bounded to < 10^9 by the parser; `newSize = (num+1+255) & ~255` is ~10^9, triggering `gMemError` in `greallocn` (10^9 > INT_MAX/16 = 134217727).

**`ObjectStream` constructor**: `nObjects` is capped at 1,000,000; `offsets` are validated non-negative and non-decreasing; `EmbedStream` lengths use the difference (non-negative, bounded by actual stream data).

**`gen` parsing in `readXRefTable`** (lines 594-598): Missing overflow guard (contrast with `first` and `n` which have guards). An attacker can overflow `gen` to a negative value — but `gen` is stored in `entry.gen` and used only for equality comparison, with no allocation from `gen`, so this is purely a logic bug (gen-mismatch bypass), not a memory safety issue.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
