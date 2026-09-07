After comprehensive analysis of all critical attack surfaces in xpdf 4.06 — Stream.cc (LZW/Flate/CCITTFax/DCT/StreamPredictor), XRef.cc (all cross-reference and object-fetch paths), JBIG2Stream.cc (all segment types and bitmap operations), FoFiType1C.cc (CFF charstring decoder), FoFiTrueType.cc (TrueType parser), and GString.cc — no exploitable memory safety vulnerabilities reachable from pdftotext were found.

Key findings:
- `FoFiType1C::getGlyphName(int gid)` has an unchecked `charset[gid]` OOB read (line 171), but the function is **never called** anywhere in the xpdf codebase
- JBIG2 `iaidStats` size matches `symCodeLen` via `resetIntStats()` before each `decodeIAID()` call — safe
- All allocation size computations have integer overflow guards (`gmallocn`, `greallocn`, inline checks)
- All array accesses in stream decoders are bounded by loop conditions or explicit checks

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
