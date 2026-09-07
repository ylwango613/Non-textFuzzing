After completing the full audit of `matroskavideo.hpp` and `matroskavideo.cpp` with all related helpers:

**Batch 1 (lines 1–600)**: Tag lookup tables and EBML enum definitions. No memory operations. The `returnTagValue()` function has `enforce(size > 0 && size <= 8, ...)` guard preventing zero/oversized sizes.

**Batch 2 (lines 600–943)**: Core parsing logic. Key analysis:

- `decodeBlock()` (line 635): enforces `size <= bufMaxSize = 200` before any read; allocates `DataBuf buf2(bufMaxSize + 1)` = 201-byte `std::vector<byte>` which **zero-initializes** all elements (`Blob = std::vector<byte>`, confirmed in types.cpp line 102).
- All decode functions (`decodeInternalTags`, `decodeIntegerTags`, `decodeBooleanTags`, `decodeFloatTags`, `decodeDateTags`) call `getULongLong(buf, bigEndian)` (reads 8 bytes) or `getFloat` (reads 4 bytes) on the 201-byte buffer — all accesses are within bounds even when `size < 8`.
- `decodeStringTags`: `xmpData_[tag->_label] = buf` where `buf = buf2.data()`. Since `buf2` is zero-initialized, there is always a null byte at `buf2[200]`, guaranteeing null termination. No OOB read.
- No recursive descent — the parser is fully iterative (`while(continueTraversing_)` in `readMetadata()`), so no stack overflow from crafted nested elements.
- Large-size elements (`size > 200`) are skipped via `io_->seek(size, BasicIo::cur)` without buffer allocation.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
