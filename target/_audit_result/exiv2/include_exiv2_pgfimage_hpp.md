I've now traced all critical paths:

**Summary of analysis:**

1. **`readPgfHeaderStructure` indexed-color path** (line 273): `header.alloc(16 + 768)` calls `std::vector::resize(784)`, which preserves the first 16 bytes. `header.data(16)` then returns `&pData_[16]` (valid, since 16 < 784). `iIo.read()` checks actual bytes read. No OOB.

2. **`readMetadata` size underflow** (line 91): `size = headerSize + 8 - io_->tell()` can unsigned-wrap, but `if (size > io_->size() - offset)` catches the enormous wrapped value and throws. The `enforce()` call is a runtime throw (not `assert`), so it works in release builds too.

3. **`mmap()` null check**: `FileIo::mmap()` always throws (never returns null); `MemIo::mmap()` can return null but PGF's own `io_` is always `FileIo` in the read path.

4. **`byteSwap_`** (lines 39-50): all accesses via `buf.read_uint8(offset+i)` / `buf.write_uint8(offset+i,…)` — both are bounds-checked and throw `std::out_of_range`.

5. **`doWriteMetadata` truncation** (line 179): `static_cast<uint32_t>(header.size() + imgSize)` can truncate, but this is the write path — it corrupts output metadata but causes no memory corruption during parsing.

6. **`DataBuf::data(offset)` returns null when `offset == pData_.size()`** — this never occurs in the indexed-color path since after `alloc(784)`, `data(16)` is valid (16 < 784).

All memory accesses in the read path are guarded by either DataBuf bounds checks, I/O read-count verification, or explicit size guards.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
