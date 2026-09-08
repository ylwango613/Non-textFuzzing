After exhaustive multi-pass analysis of the full 794-line file and its complete call chain, I have my final determination.

**Group 1 (lines 1–400): Data tables + HeaderReader + readMetadata/readList/readChunk**
- `HeaderReader` has a harmless off-by-one (`>` vs `>=` for remaining bytes)
- `readList` falls through silently for unknown list types without consuming data → misaligned parsing but no memory corruption
- All `readStringTag`/`readDWORDTag`/`readWORDTag`/`readQWORDTag` helpers each have `enforce(length <= io->size() - io->tell())` prior to allocation

**Group 2 (lines 400–580): readAviHeader / readStreamHeader**
- `1000000. / TimeBetweenFrames` where `TimeBetweenFrames=0` gives IEEE 754 infinity, not undefined behaviour
- Conditional skipping when `divisor==0` causes field misalignment — wrong metadata values but every read is file-size-bounded

**Group 3 (lines 581–680): readStreamFormat**
- BITMAPINFOHEADER `biXPelsPerMeter`/`biYPelsPerMeter` are read as QWORD (8 bytes) instead of two DWORDs, causing two additional DWORD reads beyond the 40-byte chunk boundary — cross-chunk read, but bounded by `io->size()`
- WAVEFORMATEX parsing uses DWORD for WORD fields → off-by-field alignment, not OOB

**Group 4 (lines 657–680): readInfoListChunk**
- RIFF spec requires 1-byte pad when content size is odd; the loop does not add padding to `current_size` — next sub-chunk header is read from wrong offset, potentially misinterpreting a large "size" field from attacker-controlled data
- However, `readStringTag(io_, large_size)` is bounded by `enforce(large_size <= io->size() - io->tell())` → cannot read beyond file

**Group 5 (lines 681–749): readMoviList / readVPRPChunk / readIndexChunk / readDataChunk / readJunk**
- `readMoviList`: `tell() + size_ - DWORD` when `size_ < DWORD` causes unsigned underflow and a backward seek → semantically wrong, exits loop cleanly on next `tell() < size()` check

**DataBuf / IO safety net** (confirmed in `types.cpp` / `basicio.cpp`):
- `DataBuf::read_uint16/32/64` all do explicit bounds checks before dereferencing
- `FileIo::read(size_t)` checks `rcount > size()` and `readCount == 0`
- `BasicIo::readOrThrow` checks `nread == rcount`
- `MemIo::seek` refuses seeks beyond EOF (returns 1)
- `FileIo::seek` (via `fseeko`) can seek past EOF, triggering the unsigned underflow in `enforce(N <= io->size() - io->tell())`, but subsequent `readOrThrow` / `read_uint32` catches the partial/zero read and throws before any memory corruption

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
