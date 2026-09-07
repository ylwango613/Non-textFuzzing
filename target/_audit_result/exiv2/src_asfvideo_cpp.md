After reading the full 496-line file in two passes and tracing every read helper, I found:

**Batch 1 (lines 1–250): GUID table, `GUIDTag` constructor, `decodeBlock`, top of `decodeHeader`**
- `GUIDTag(const uint8_t* bytes)` accesses bytes[0..15] — always called with a GUID-sized (16-byte) buffer, safe.
- `decodeBlock` enforces `GUID+QWORD <= io_->size()-io_->tell()` and `objectHeader.getSize() <= remaining`. Unsigned underflow of `size()-tell()` can occur for FileIo past-EOF; however, subsequent code paths all throw before any memory access.
- Recursion: `decodeBlock(depth)` → `decodeHeader(depth+1)` → `decodeBlock(depth)`. Depth check enforces `depth <= 1000`; ~2000 frames at ~200 bytes each is well within 8 MB stack.

**Batch 2 (lines 250–496): All handler functions**
- `codecList()` line 375: `uint16_t codec_name_length = readWORDTag(io_) * 2` — integer truncation overflow (parsing misalignment), not memory corruption.
- `extendedContentDescription()`: Fixed-size types (BOOL, DWORD, QWORD, WORD) consume wrong byte counts vs `descriptor_value_length` — parsing confusion, not memory corruption.
- `readStringWcharTag`: `DataBuf(length+1)`, `end()-3` — enforced `length>=2` keeps the iterator subtraction in-bounds.

**Helper function analysis (`helper_functions.cpp`):**
- `DataBuf::read_uint16/32/64` all have explicit bounds checks and throw `std::out_of_range` before any out-of-bounds access.
- `FileIo::read()` throws when `fread` returns 0 bytes (EOF).
- `readOrThrow` enforces `nread == rcount`, catching partial reads.
- `MemIo::seek` clips to EOF (does not advance `idx_` past `size_`), preventing unsigned underflow in subsequent `size()-tell()` expressions.

All potential OOB paths terminate in a thrown exception before actual memory access, due to redundant defensive layers (DataBuf bounds checks + enforce + readOrThrow + FileIo::read throw-on-zero).

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
