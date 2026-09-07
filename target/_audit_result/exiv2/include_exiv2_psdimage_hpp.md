After fully reading all 703 lines of `psdimage.cpp` in two batches, examining the `NativePreview` struct definition, the `enforce` implementation, and the `getLong`/`getULong` helpers, here is my complete analysis:

**Key findings per attack surface:**

1. **IPTC/Exif/XMP DataBuf allocation** (lines 216, 230, 247): `resourceSize` is bounded by `enforce(resourceSize <= resourcesLength)` at line 203, and `resourcesLength < io_->size()` at line 169. No integer overflow path leads to underallocation.

2. **Thumbnail header read without minimum size check** (lines 281-306): No check that `resourceSize >= 28` before the 28-byte stack-buffer read. Reads can bleed into adjacent resource data, but `buf[28]` is fully stack-allocated; no memory corruption results.

3. **`getLong()` (int32_t) assigned to `size_t`** for thumbnail `size_`, `width_`, `height_` (lines 287-289): Negative int32_t sign-extends to huge `size_t`. For `size_`, the `enforce` at line 292 throws. For `width_`/`height_`, no enforce — but within this file they are only stored, never used for allocation.

4. **`(resourceSize + 1) & ~1` overflow** (line 205) when `resourceSize = 0xFFFFFFFF`: Result wraps to 0. The second `enforce(0 <= resourcesLength)` always passes, and the seek returns to `curOffset + 0`. Subsequent iteration hits `enforce(resourcesLength >= 8)` or breaks on `isIrb`. No memory corruption.

5. **`doWriteMetadata` `oldResLength` underflow** (line 502): `adjResourceNameLen` (max 254) + `pResourceSize` can exceed `oldResLength`. Wraps to large value, extra loop iterations fail safely on `io_->read` EOF checks.

6. **`enforce` is production-effective**: It throws `Exiv2::Error`, not an assert — guards work in release builds.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
