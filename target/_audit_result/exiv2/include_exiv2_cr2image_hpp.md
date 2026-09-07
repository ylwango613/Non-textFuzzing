Now I have a comprehensive understanding of the CR2 image parsing code. Let me compile the final analysis.

The CR2 header file (`cr2image.hpp`) declares `Cr2Image` and `Cr2Parser` classes that delegate all real work to `TiffParserWorker`. The actual vulnerability surface is in the TIFF parsing chain called via `readMetadata()` and `printStructure()`.

Key findings from the analysis:
1. `cr2header_int.cpp` — size-checked (size < 16 guard), safe
2. `TiffParserWorker::parse` — properly validates `pHeader->offset() >= size`
3. `TiffReader::readTiffEntry` — integer overflow in `count * typeSize` is guarded; offset bounds are checked via `Safe::add`; size is truncated to 0 when out of bounds
4. `TiffReader::visitDirectory` — entry count capped at 256; circular IFD chains caught by `circularReference`
5. `TiffReader::visitSubIfd` — count comes from parsed Value (bounded), `maxi=9` limits sub-IFDs
6. `ValueType<T>::read` — reads exactly `len` bytes in chunks of `ts` bytes; no OOB
7. **`Image::printIFDStructure` with `kpsRecursive`** — **unbounded recursion** through SubIFD/ExifTag entries without any depth limit

The `kpsRecursive` path (triggered by `exiv2 -pR <file>` in debug builds, or `image->printStructure(out, kpsRecursive)` via library API, and directly by the official fuzzer `fuzz-read-print-write.cpp:42`) calls `printIFDStructure` recursively for every SubIFD (tag 0x014a), ExifTag (0x8769), or `tiffIfd`-typed entry found in the parsed directory. The `visits` set only prevents visiting the *same entry position* twice — it does NOT limit recursion depth across a linear chain of unique IFDs. A crafted CR2 file with ~27,000 unique nested sub-IFDs (< 500 KB) exhausts the default 8 MB stack.

## VULN: Stack Overflow via Unbounded Recursion in printIFDStructure kpsRecursive Mode
- **漏洞类别**: memory-safety
- **函数**: `Image::printIFDStructure()`
- **行号**: image.cpp:326-521 (recursive calls at lines 462, 497, 502)
- **CWE**: CWE-674 (Uncontrolled Recursion)
- **CVSS v3.1**: 5.5 (AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted image file
- **外部触发路径**: `exiv2 -pR <file>` (debug builds) / library API `Cr2Image::printStructure(out, kpsRecursive, depth)` → `Image::printTiffStructure(io, out, kpsRecursive, depth)` → `Image::printIFDStructure(io, out, kpsRecursive, start, bSwap, c, depth)` → recursive call at line 462 for each SubIFD (tag 0x014a) or ExifTag (0x8769) or `tiffIfd`-typed entry → `Image::printIFDStructure(..., depth+1)` → …
- **描述**: `printIFDStructure()` recursively calls itself for every TIFF IFD entry with tag `0x8769` (ExifIFD), `0x014a` (SubIFDs), or any entry with type `tiffIfd` (line 458–463), each time incrementing `depth` with no upper bound check. The anti-loop protection (`visits` static set, line 354–357) only prevents revisiting the same file offset for an IFD *entry* read, not the same IFD *directory*. A linear chain of N IFDs at unique offsets — where each IFD contains exactly one SubIFD entry pointing to the next — produces N levels of C++ call-stack recursion without any guard, leading to stack exhaustion.
- **触发条件**: Craft a CR2 (TIFF) file whose first IFD contains a SubIFD entry (type=tiffIfd, count=1) pointing to a second IFD, which in turn has a SubIFD pointing to a third, and so on. Each IFD requires ≥18 bytes (2-byte count + 12-byte entry + 4-byte next-IFD pointer). A 500 KB file provides ~27,000 nesting levels; with a typical 300–500 byte stack frame per `printIFDStructure` call, this overflows the default 8 MB thread stack. The file must pass the `isCr2Type` 16-byte signature check (II/MM + 0x002A + offset + CR\x02\x00 magic). Trigger via `exiv2 -pR <file>` (debug build) or any library consumer calling `image->printStructure(out, Exiv2::kpsRecursive)`.
- **安全影响**: Immediate process crash (denial of service) via stack overflow; on platforms without stack canaries or with exploitable stack-layout, adjacent stack-frame corruption may enable arbitrary code execution. The official fuzzer `fuzz-read-print-write.cpp:42` exercises this code path unconditionally from untrusted input, confirming real exploitability in fuzzing/library-API contexts.

<!-- AUDIT_PROMPT_VERSION: 1 -->
