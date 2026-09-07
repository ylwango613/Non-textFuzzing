After thorough analysis of `cr2header_int.hpp` and its implementation `cr2header_int.cpp`, along with the full call chain through `TiffParserWorker::parse()` and all DataBuf methods:

- `Cr2Header::read()` validates `size >= 16` before any byte access; all accesses (offsets 0–15) are within that bound.
- `Cr2Header::write()` allocates exactly 16 bytes and writes only to offsets 0–15; DataBuf's `write_uint*` methods throw `std::out_of_range` on overrun, so no silent OOB write.
- `offset2_` is stored from attacker-controlled bytes 12–15 but is **never exposed through any getter and never used as a pointer or index**; `write()` writes the constant `0x00000000` to that slot, and `offset2addr()` returns the compile-time constant `12`.
- The `cr2RawIfdOffset` / `OffsetWriter` machinery only operates on the encode (write) path and does not use the parsed `offset2_` value.
- `TiffParserWorker::parse()` guards the root IFD offset with `pHeader->offset() >= size` before any IFD traversal.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
