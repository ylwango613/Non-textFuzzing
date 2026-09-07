The ncrypt function is safe — it iterates exactly `size` bytes (`buf.size() - nci->start_`) over the `buf` that was just allocated to exactly `size` bytes, and the caller already verified `nci->start_ < size`.

After completing examination of all major parsing paths across:
- `tiffvisitor_int.cpp` — readTiffEntry, visitDirectory, visitSubIfd
- `tiffcomposite_int.cpp` — DataEntry, ImageEntry, BinaryArray
- `iptc.cpp` — IptcParser::decode/encode
- `photoshop.cpp` — Pascal string handling (logic bug but not OOB)
- `bmffimage.cpp` — boxHandler, iloc, parseTiff, parseCr3Preview
- `jpgimage.cpp` — JPEG segment parsing
- `rafimage.cpp` / `psdimage.cpp`
- `makernote_int.cpp` — Nikon ncrypt, Sony/Nikon makernote creators
- `types.cpp` — DataBuf bounds-checked accessors

The codebase consistently employs `Internal::enforce()`, `Safe::add<T>()`, `DataBuf` bounds-checked accessors, and `std::vector::at()` throughout all file-data parsing paths. The one integer overflow found (`uint16_t count` accumulator in `decodeCanonAFInfo`) leads only to a `std::out_of_range` exception via `ints.at()` — not memory corruption.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
