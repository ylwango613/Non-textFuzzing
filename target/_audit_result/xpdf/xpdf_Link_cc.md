After reading all 922 lines of Link.cc in batches and cross-checking GString internals, gmem, Object, and Catalog.cc, here is the complete assessment:

**Batch 1 (lines 1–450):** `LinkAction::parseAction`, `getFileSpecName`, `LinkDest::LinkDest` — Windows path manipulation uses GString insert/del (self-resizing, safe). FitR error-continuation calls `getNum()` on non-numeric Object (reads union `real` field with garbage, logic bug only, no memory write). All array accesses in `LinkDest` are bounds-checked before use.

**Batch 2 (lines 450–922):** `LinkJavaScript` reads stream into a 4096-byte stack buf via `getBlock(buf, sizeof(buf))` — the size argument caps what `getBlock` can write. `GString::append(buf, n)` has its own negative-length check at line 249 of GString.cc. `LinkURI::LinkURI` calls `getChar(uri->getLength()-1)` which would be `getChar(-1)` (heap OOB) for an empty baseURI, but Catalog.cc (lines 193–205) explicitly replaces empty/null baseURI before it reaches here. `Links::Links` uses `greallocn` which checks `nObjs * objSize` overflow. `GString::getChar` has no bounds check but every call-site here uses a valid non-negative index.

**Result:** No exploitable memory-safety vulnerability is reachable via a crafted PDF in Link.cc under normal execution paths.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
