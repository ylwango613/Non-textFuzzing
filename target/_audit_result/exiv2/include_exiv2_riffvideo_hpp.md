After systematically reading all of `riffvideo.cpp` (795 lines), `helper_functions.cpp/hpp`, `types.cpp` (`DataBuf::read_uint*`), `basicio.cpp` (`FileIo::read`), and `enforce.hpp`, my findings are:

**Protective mechanisms confirmed:**
- Every IO read function (`readDWORDTag`, `readQWORDTag`, `readWORDTag`, `readStringTag`) calls `Internal::enforce(n <= io->size() - io->tell(), ...)` before every allocation/read — guaranteed throw on OOB
- `DataBuf::read_uint16/32/64` each check `pData_.size() < N || offset > (pData_.size() - N)` and throw `std::out_of_range` — no silent OOB
- `FileIo::read(rcount)` calls `buf.resize(readCount)` on short reads, and subsequent `read_uint64` would throw on undersized buffer
- No recursion in the RIFF parser (iterative `decodeBlocks` loop, no depth limit needed)
- `DataBuf(length + 1)` in `readStringTag`: on 64-bit, `length` is bounded by `uint32_t` → max `0xFFFFFFFF + 1 = 0x100000000` — no integer overflow

**Parsing bugs found (not memory safety):**
- `readStreamFormat` uses `readQWORDTag` (8 bytes) for `biXPelsPerMeter`/`biYPelsPerMeter` which are each DWORDs — causes cross-chunk data consumption but all reads are file-bounds-checked
- `readStreamHeader` with `divisor == 0` desynchronizes IO position by 8 bytes — causes wrong chunk header parsing downstream
- `readInfoListChunk` missing RIFF 2-byte alignment padding for odd-sized INFO tag content — parsing desync, not OOB
- Float division-by-zero in `fillDuration` when `TimeBetweenFrames == 0` produces IEEE 754 Inf, no memory impact

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
