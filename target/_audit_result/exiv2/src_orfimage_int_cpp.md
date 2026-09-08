`DataBuf(size_t)` constructs `std::vector<byte>(size)`, which zero-initializes all elements — the `default` branch in `write()` is safe.

**Full analysis summary of `orfimage_int.cpp`:**

- **`OrfHeader::read()`** (lines 9–27): `size < 8` guard is checked before any byte access. All reads (`pData[0]`, `pData[1]`, `pData+2`, `pData+4`) are within the first 8 bytes. The 4-byte IFD offset stored via `setOffset()` is later validated in `TiffParserWorker::parse()` with `pHeader->offset() >= size` before any pointer arithmetic.
- **`OrfHeader::write()`** (lines 29–46): `DataBuf(8)` zero-initializes 8 bytes. All `write_uint8/16/32` calls have internal bounds checks that throw `std::out_of_range` on overflow. Positions written (0, 1, 2–3, 4–7) are all within the 8-byte buffer. The `default` branch leaves position 0 as `0x00`; subsequent `read_uint8(0)` returns `0` (defined, not UB).
- **`getUShort`/`getULong`** raw-pointer variants do no bounds checking themselves, but they are only called here after the `size < 8` guard makes the accesses safe.
- No integer overflow, heap underallocation, OOB read/write, UAF, or recursive stack issue is reachable through this file's 49 lines of code.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
