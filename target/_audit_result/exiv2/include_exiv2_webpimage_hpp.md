Complete analysis done. Summary of findings:

- `DataBuf::c_data()`, `read_uint8()`, etc. all perform runtime bounds checking and throw `std::out_of_range` on violation.
- `Internal::enforce()` throws `Exiv2::Error` on constraint violation — not a simple assert.
- Every chunk size in `decodeChunks()` and `doWriteMetadata()` is validated via `Internal::enforce(size <= io_->size() - io_->tell(), ...)` before any allocation or read.
- `Safe::add()` in `readMetadata()` protects the filesize+8 computation from integer overflow.
- The `getHeaderOffset()` has an off-by-one (`i < data_size - header_size` should be `<=`) that can miss a header at the last position — a functional bug, not a memory-safety issue.
- `rawExifData` is built but never consumed (dead code) — no memory corruption path.
- All `std::copy_n` / `std::copy` destinations in the EXIF header reconstruction fit exactly within the allocated `rawExifData` buffer.
- The delegation to `ExifParser::decode()` and `XmpParser::decode()` passes validated lengths, though those parsers' own internals are outside this file's scope.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
