Complete analysis of all code paths in `pgfimage.cpp`:

**`byteSwap_` (lines 38-49)**: All four `read_uint8`/`write_uint8` calls are bounds-checked — each throws `std::out_of_range` on OOB. All call sites use correctly-sized buffers: 4-byte buffer at offset 0, or 8-byte buffer at offsets 0 and 4.

**`readPgfHeaderSize` (lines 232-249)**: 4-byte DataBuf, reads exactly 4 bytes, `byteSwap_` at offset 0 — no OOB possible.

**`readPgfHeaderStructure` (lines 251-282)**: 16-byte header read, optional `alloc(784)` + 768-byte read at offset 16. `DataBuf::c_data(16)` throws if offset > size, but size is 784 after alloc. No OOB.

**`readMetadata` (lines 66-112)** — most complex path:
- `enforce(headerSize <= size_t::max - 8)` guards the addition
- `size = headerSize + 8 - io_->tell()`: unsigned underflow if `tell() > headerSize+8`, but the resulting huge `size` is immediately caught by `size > io_->size() - offset` check at line 99 → exception thrown
- `base + offset` to `base + offset + size`: protected since `offset + size <= io_->size()` is enforced; mmap covers the full file

**`doWriteMetadata` (lines 127-214)**: `static_cast<uint32_t>(header.size() + imgSize)` can truncate for huge metadata, but only corrupts the written header field — no memory corruption in-process.

**`isPgfType` (lines 294-307)**: Reads 3 bytes, checks error/eof, seeks back if needed — clean.

All DataBuf accessors (`read_uint8`, `write_uint8`, `c_data`, `read_uint16`, `read_uint32`) uniformly throw `std::out_of_range` on any OOB access. No raw pointer arithmetic without bounds validation was found.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
