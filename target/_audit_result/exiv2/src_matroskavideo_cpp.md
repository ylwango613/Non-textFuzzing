`pData_` is `Blob` = `std::vector<byte>`, so `DataBuf(size_t size)` calls the vector constructor that value-initializes all bytes to 0. This confirms `DataBuf buf2(201)` creates 201 zero bytes.

**Group 1 analysis (lines 1-593):** Tag tables, enum definitions, `returnTagValue()`. The `enforce(size > 0 && size <= 8, ...)` check prevents zero-size invocations. Shifting `0xff >> size` is always within int range. No issues.

**Group 2 analysis (lines 635-716 — `decodeBlock`):**
- `buf[8]` on stack. `findBlockSize` returns 0–8; read is bounded to `block_size - 1` ≤ 7 additional bytes. No overflow.
- `block_size = 0` case: guarded by `if (block_size > 0)` before `readOrThrow`; `returnTagValue(buf, 0)` throws via `enforce`. No OOB.
- `size = returnTagValue(buf, block_size)` can be up to 2^56. The check `size > bufMaxSize` (200) at line 681 routes to `io_->seek(size, cur)` — a large forward seek, not a memory operation. DoS at worst.
- `DataBuf buf2(201)` then `io_->readOrThrow(buf2.data(), size, ...)` with `size ≤ 200`: always safe.

**Group 3 analysis (lines 718-895 — decode functions):**
- `getULongLong(buf2.data(), bigEndian)` reads bytes 0–7 from a 201-byte buffer. Always in-bounds even when `size < 8` (remaining bytes are 0 from zero-init).
- `getFloat` reads 4 bytes; `getDouble` reads 8 bytes — both within 201-byte buf2.
- `xmpData_[tag->_label] = buf;` in `decodeStringTags`: buf2 is zero-initialized, so `buf2.data()[size] = 0` is always a valid null terminator. Safe.
- `decodeDateTags` with `size <= 4` calling `getFloat` (4 bytes), or `> 4` calling `getDouble` (8 bytes): both within 201-byte buf2.

**Group 4 analysis (lines 897-942 — `findBlockSize`, `isMkvType`):** Simple bitmask operations on a single byte. No memory operations. Clean.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
