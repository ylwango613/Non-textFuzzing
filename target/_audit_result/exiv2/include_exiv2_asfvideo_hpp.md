I've now completed a thorough multi-pass analysis of the full call chain:
- `asfvideo.hpp` / `asfvideo.cpp` (all parsing functions)
- `helper_functions.cpp` (readWORDTag / readDWORDTag / readQWORDTag / readStringTag / readStringWcharTag)
- `basicio.cpp` (FileIo::read, FileIo::seek, FileIo::tell, FileIo::size, MemIo::read, MemIo::seek, readOrThrow)
- `types.cpp` (DataBuf::read_uint16/32/64 — all throw on OOB)
- `enforce.hpp` (throws exceptions on failed conditions)

**Key findings during analysis:**

**Group 1 — Logic bugs (not memory safety):**
- `codecList()` line 372: `uint16_t codec_type = readWORDTag(io_) * 2` → codec_type is always even, so `codec_type == 1` is never true; all codecs are labelled "Xmp.audio".
- `codecList()` line 378: `codec_desc_length` is not multiplied by 2 (unlike `codec_name_length`), causing misaligned reads after the description field.
- `extendedContentDescription()` lines 412–425: for BOOL/DWORD/QWORD/WORD types, the code reads fixed-size data (2/4/8/2 bytes) ignoring `descriptor_value_length`, causing future descriptors to be read from the wrong offset. Unknown types (≥6) have no default case, so `descriptor_value_length` bytes are never consumed, causing the same misalignment.
- `readStringWcharTag()` line 46–47: for odd-length strings, `convertStringCharset` is called twice (once inside the `if`, once unconditionally after).

**Group 2 — Unsigned underflow via `size() - tell()` (potential enforce bypass):**
- For FileIo, `fseeko` allows seeking past EOF. If tell > size, `io->size() - io->tell()` underflows to a huge `size_t`. The `enforce(N <= huge)` check always passes. However, the downstream `FileIo::read(n)` throws `kerInputDataReadFailed` when `fread` returns 0 bytes at EOF. `DataBuf::read_uint*` throws `std::out_of_range` if the DataBuf is undersized. `readOrThrow` throws if fewer than `rcount` bytes were read. So no path leads to memory corruption.
- For MemIo, `seek` refuses to advance `idx` past `size_`, so `size() - tell()` never underflows.

**Group 3 — Recursion depth:**
- `decodeBlock(depth)` → `decodeHeader(depth+1)`: `decodeHeader` enforces `depth <= max_recursion_depth_ = 1000`. Correctly bounded.

**Conclusion:** Every read path in `asfvideo.cpp` is protected by at least one of: `enforce` bounds checks, `DataBuf::read_uint*` OOB throws, `readOrThrow` short-read detection, or `MemIo::seek` EOF clamping. No exploitable heap overflow, OOB write, OOB read, UAF, or stack overflow was found.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
