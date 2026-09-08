Having read all 703 lines of `psdimage.cpp` in full and traced every relevant call chain, here is my complete analysis:

**Read path (`readMetadata` + `readResourceBlock`):**
- All resource-length accounting uses layered `Internal::enforce()` calls (lines 169, 172, 185, 190, 203, 206). Each enforce throws on violation, so `DataBuf(resourceSize)` allocations are always bounded by remaining file bytes.
- The `(resourceSize + 1) & ~1` padding overflow scenario (resourceSize = 0xFFFFFFFF) is geometrically impossible: max reachable `resourceSize` after the mandatory 12-byte subtraction from `resourcesLength` is `io_->size() - 13`, which on any realistic file cannot reach 0xFFFFFFFF to trigger the uint32 wrap.
- `nativePreview.size_` from `getLong` (int32_t → size_t) is guarded by enforce at line 292; the preview reading path in `preview.cpp:402` additionally bounds-checks `position_ + size_ <= io.size()` before any pointer arithmetic.

**Write path (`doWriteMetadata`):**
- `pResourceSize = (resourceSize + 1) & ~1` at line 436 has no enforce, so resourceSize = 0xFFFFFFFF → pResourceSize = 0 (overflow). This causes `io_->seek(curOffset + 0)` and only a 12-byte decrement per iteration, creating a long spin loop → DoS only, not memory corruption.
- `oldResLength` is never validated against `io_->size()`, same DoS-class issue.

**No `memcpy`/`strcpy`/`sprintf` or unsafe raw-pointer arithmetic present in this file.**

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
