**Batch 1 findings (lines 1–356, entire file read):**

**`undoPFB()` (lines 323–355):** `file2 = gmalloc(len)`. Each PFB segment is validated with `checkRegion(pos1, segLen)` before `memcpy`. `checkRegion` accepts `int size` and the `segLen` (`Guint`) cast to `int` makes oversized values negative, failing `size >= 0`. The accumulator `pos2 += segLen` can never reach `len` because every segment's source region plus its 6-byte header must fit within the original file, so the sum of all `segLen` values is bounded by `len − 6 × numSegments`. No OOB write.

**`parse()` encoding block (lines 220–288):** `encoding = gmallocn(256, sizeof(char *))` exactly 256 slots. `code` is `Guint` and can arithmetically wrap, but `if (code < 256)` guard prevents any out-of-bounds index. `endsWithDup` reads `line − 4` and `line − 5`; the earliest `line` can be at this point is `file + 20` (after the 20-byte "/Encoding 256 array\n" line), so these backward reads are within the file buffer.

**`parse()` FontName / FontMatrix blocks:** Stack buffer `buf[256]` used with `n` capped at 255, then `buf[n] = '\0'` — safe.

**`writeEncoded()`:** `snprintf(buf, sizeof(buf), ...)` with 512-byte buf — safe. All pointer arithmetic against `(char *)file + len` — safe.

**`getNextLine()`:** All dereferences guarded by bounds check — safe.

After a complete read of all 356 lines and cross-referencing `FoFiBase.cc`, `gmem.h`, and the type definitions, no exploitable memory safety vulnerability is present.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
