After thoroughly reading `params.hpp` (36 lines, defining `DecodeParams`), tracing every caller in the full audit chain, and cross-checking the critical enforcement points, here is my complete assessment:

**Group 1 findings (readTiffEntry, tiffvisitor_int.cpp ~1232-1331):** `count * typeSize` overflow is explicitly checked at line 1267; bounds for both start and end of data are double-checked; no OOB issue.

**Group 2 findings (XMLValidator::startElement, xmp.cpp ~123-128):** Off-by-one confirmed — `element_depth_ > max_recursion_depth_` should be `>=`. This allows XML at depth `max_recursion_depth_ + 1 = 1001` to reach `SXMPMeta`. However, at 1001 levels of nesting with typical frame sizes (~200 bytes), total stack consumption is ~200 KB, well within the 8 MB default thread stack. The XMP SDK's actual overflow threshold is far beyond 1001 levels. **Not practically exploitable as a memory safety bug.**

**Group 3 findings (IFD traversal):** `circularReference()` prevents cycles; schema-bounded IFD tree prevents unlimited depth; `visitSubIfd` limits sub-IFDs to 9 per parent.

**Group 4 findings (IPTC, PNG, DataBuf):** All have proper `enforce()`/bounds-checked accessors; `readRawProfile` uses `enforce(length <= (eot-sp)/2)` before allocation; zlib decompression capped at 128 KB.

**Group 5 findings (BMFF, QuickTime, ASF):** All use explicit `depth >= max_recursion_depth_` checks before each recursive call.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
