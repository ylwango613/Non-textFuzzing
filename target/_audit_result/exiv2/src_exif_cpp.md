I've now read all 749 lines of `exif.cpp` in two batches and investigated the key callees. Let me summarize my findings from each section:

**Batch 1 (lines 0–600):** High-level wrapper methods—`Exifdatum` get/set accessors, `ExifThumb` thumbnail management, `ExifData` collection operations, and `ExifParser::decode/encode`. All use modern C++ (`std::list`, `std::unique_ptr`, `Safe::add`). No raw pointer arithmetic, unchecked array indexing, or unsafe allocations.

**Batch 2 (lines 600–749):** `encode()` loop over static filter tables using `findKey/erase` on `std::list` (no iterator invalidation), `sumToLong` using `Safe::add`, `TiffThumbnail::copy` iterating a const ref and adding to a separate object, `JpegThumbnail::copy` returning `format->dataArea()`.

**Related code investigation:**

- `TiffComposite_int.cpp:273` – `setDataArea` is guarded by `size > sizeData || offset > sizeData - size || baseOffset > sizeData - size - offset` before any pointer arithmetic. Properly bounds-checked.
- `preview.cpp:734` – `Safe::add(offset, size) <= io.size()` guard before `setDataArea`.
- `ExifMetadata` is `std::list<Exifdatum>` – no iterator invalidation from `emplace_back` or `erase`.
- `sumToLong` uses `Safe::add` – no integer overflow path.
- `ExifParser::decode` delegates to `TiffParser::decode` which enforces bounds at the TIFF layer.

No memory safety vulnerabilities (OOB read/write, integer overflow leading to underalloc, iterator invalidation, recursive stack overflow, UAF) are present in `exif.cpp` or its direct callees within the scope of external input processing.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
