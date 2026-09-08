I have now fully read `WXMPUtils.cpp` (all 627 lines) and traced every function it calls into `XMPUtils.cpp` and `XMPUtils-FileInfo.cpp`. Here is my complete analysis:

**WXMPUtils.cpp itself** is a pure C-linkage wrapper with no direct memory operations. Every function validates NULL pointers then delegates straight to `XMPUtils::*` methods.

**Functions examined in depth:**

- `XMPUtils::DecodeFromBase64` (XMPUtils.cpp:1550–1663): Has a real heap OOB read. The final-chunk loop at line 1630 (`for (inChunk = 0; inChunk < 4-padding; ++inStr)`) reads past `encodedLen` when the inner loop in the outer `while(inStr < inLimit)` absorbs data bytes that belong to the final chunk, leaving fewer than `4-padding` bytes for the final loop with no upper-bound guard. Example: input `"A\nBCDE"` causes the final chunk loop to go 1+ bytes past the buffer. In release builds `XMP_Assert` (line 1627) is a no-op (`#define XMP_Assert(c) ((void) 0)`). However, **exiv2 never calls `SXMPUtils::DecodeFromBase64` or `WXMPUtils_DecodeFromBase64_1` during image parsing** (`grep` across all of `src/` confirms zero callers). This makes it unreachable via `exiv2 pr <file>`.

- `XMPUtils::ConvertToDate` / `ConvertToLocalTime` (called from `convert.cpp`): The only `XMPUtils` methods actually invoked by exiv2 during metadata reading. Integer parsing uses `GatherInt` which has explicit overflow protection (lines 377–388). No memory-safety issues.

- `XMPUtils::PackageForJPEG`, `MergeFromJPEG`, `CatenateArrayItems`, `SeparateArrayItems`, `DuplicateSubtree`, `AppendProperties`: All operate on already-parsed `XMP_Node` trees (`std::string` / `std::vector`) with no raw-buffer indexing. No reachable memory-safety bugs.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
