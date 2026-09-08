The file `rw2image_int.hpp` is 37 lines — a pure class declaration with no implementation logic. I've read the `.cpp` implementation and the entire parsing call chain (base class `TiffHeaderBase::read`, `TiffParserWorker::parse`, and `isRw2Type`). Key findings:

- `Rw2Header` only delegates to `TiffHeaderBase` with compile-time constants; it adds no logic.
- `TiffHeaderBase::read` checks `size < 8` and validates `offset_ < file_size` before use in `TiffParserWorker::parse` (line 2121).
- `write()` is a stub returning empty `DataBuf`.
- No allocation, memcpy, loop, or attacker-controlled value is touched in this file or its implementation.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
