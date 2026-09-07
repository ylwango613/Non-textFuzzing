Completed full read of FoFiTrueType.cc (2508 lines), FoFiBase.cc, and gmem.cc. Key findings from each analysis pass:

**Pass 1 (parse(), cmap loop):** `cmaps[k].offset` gets a `Guint` value cast to `int`; negative values slip past the `cmaps[k].offset >= tables[i].len` check. But subsequent `getU16BE(cmaps[k].offset, &parsedOk)` bounds-checks and sets `parsedOk=gFalse` → parse failure, no memory write.

**Pass 2 (mapCodeToGID format 4/12):** Integer sums like `pos + 16 + 6*segCnt + 2*b + segOffset + 2*(c-segStart)` can only exceed INT_MAX for a ~2GB cmap table; signed overflow → wrapped negative → `getU16BE` rejects `pos < 0`. Format 12 `segCnt` stored as `int` but value 0 yields `b = -1` → reads land in the cmap header, all bounds-checked.

**Pass 3 (readPostTable format 2):** Inner loop `stringPos += 1 + getU8(stringPos, &ok)` goes out-of-bounds but `getU8` returns 0 with `ok=false`; after the inner loop `if (!ok) continue` guards the subsequent access. `ok = gTrue` correctly reset each outer iteration.

**Pass 4 (writeTTF – locaTable, newHMTXTab, newNameTab):** All allocation sizes match write loop bounds. `gmallocn` itself checks for `nObjs*objSize` overflow. `nGlyphs` can never reach -1 after parse() (loca length < 2/4 causes early return before the nGlyphs adjustment).

**Pass 5 (cvtSfnts – vmtxTab, locaData):** Allocations correctly sized; loop write bounds stay within `gmallocn` size.

**Pass 6 (seekTable unchecked returns):** All call sites for seekTable in writeTTF/cvtSfnts operate on tables guaranteed to exist by parse() preconditions.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
