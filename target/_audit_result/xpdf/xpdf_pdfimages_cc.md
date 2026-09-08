I have now completed a thorough reading of the full target file `pdfimages.cc` (199 lines) and its core implementation file `ImageOutputDev.cc` (548 lines), plus all relevant supporting context:

**Group 1 analysis — `pdfimages.cc` (lines 1–199):** Pure main() boilerplate: arg parsing, PDFDoc construction, page range clamping, ImageOutputDev creation and dispatch. No direct memory manipulation.

**Group 2 analysis — `ImageOutputDev::startDoc` (lines 55–67):**  
`gmallocn(imgFileNamesSize, sizeof(GString))` uses `sizeof(GString)` (16 bytes on 64-bit) instead of `sizeof(GString *)` (8 bytes) — allocates *twice* as much memory as needed. This is a bug but is an over-allocation; no OOB write results.

**Group 3 analysis — `drawImageMask` / `drawImage` PBM loops (lines 174, 334):**  
`size = height * ((width + 7) / 8)` is a signed integer overflow for large `width`, but `size` only drives a loop counter against a fixed-size stack buffer (`buf[4096]`) capped by `i = size < (int)sizeof(buf) ? size : (int)sizeof(buf)`. No heap allocation, no stack overflow.

**Group 4 analysis — `imgFileNames` array bounds (lines 98, 194, 223, 446):**  
Checks `ref->getRefNum() < imgFileNamesSize` — upper bound only. Missing lower-bound (`>= 0`) check. However, `Parser.cc:113` explicitly validates `num >= 0 && gen >= 0` before constructing an `objRef`; negative ref nums are impossible in practice, eliminating this attack path.

**Group 5 analysis — `getRawStream` / `getRawFileExtension` (lines 479–505):**  
Cast to `FilterStream *` only for known FilterStream subclasses. No type confusion.

**Group 6 analysis — `ImageStream` constructor (Stream.cc:361–388):**  
Has explicit overflow checks: `width > INT_MAX / nComps || nVals > (INT_MAX - 7) / nBits` → forces `gmallocn(-1,...)` on overflow. Properly protected.

**Group 7 analysis — `gmallocn` in startDoc (gmem.cc:204–215):**  
Has `nObjs < 0 || nObjs >= INT_MAX / objSize` check → aborts on overflow. Properly protected.

After exhaustive analysis of all code paths, all array accesses are bounded, all allocations are overflow-protected, negative ref numbers are parser-prevented, and stack buffers are fixed-size with explicit size limits.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
