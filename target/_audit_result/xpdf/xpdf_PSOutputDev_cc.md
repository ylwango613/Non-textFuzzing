`gmallocn` at line 210 performs `nObjs >= INT_MAX / objSize` overflow protection and calls `gMemError` on violation. This confirms the last guard against integer-overflow → mis-sized allocation.

After reading all 8,620 lines of `PSOutputDev.cc` across 17 batches, every candidate was ruled out:

- `gmallocn` / `greallocn` – built-in `INT_MAX / objSize` overflow guard; safe
- `drawString()` `dxdy` resizing – `do { dxdySize *= 2; } while (nChars + uLen > dxdySize)` loop and single-step doubling with `nChars + 1 > dxdySize` both maintain strict in-bounds invariant
- `len = height * ((width * numComps * bits + 7) / 8)` – overflow is possible but `len` feeds only `FixedLengthEncoder` (stream limit), not a heap allocator
- `visitedResources[ref0.num]` – gated by `ref0.num < xref->getNumObjects()` check before any access
- `splitType1PFA/PFB` and `copyType1PFB` – `length1 <= fontSize` and `binStart <= fontSize - length2 - 4` bounds checks prevent OOB reads
- `GrayRecoder::buf = gmalloc(width)` and `doImageL1Sep: gmallocn(width, 4)` – width validated > 0 upstream; gmallocn overflow guard covers large values

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
