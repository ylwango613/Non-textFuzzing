No `memcpy`, `DataBuf`, `new[]`, or raw pointer arithmetic anywhere in the 3085-line implementation file. The one suspicious pattern (`model.substr(model.size() - 8, 8)` at line 2678) would throw `std::out_of_range` on short strings — an exception/crash, but not a memory-corruption primitive.

**Summary of full analysis:**

- **Lines 1–684**: Constant lookup tables (TagDetails, TagInfo arrays) — all `constexpr` / `const`, no runtime writes.
- **Lines 686–2665**: More tag definition tables for every Canon sub-IFD — same.
- **Lines 2666–3085**: The actual print/format functions (`printFiFileNumber`, `printFocalLength`, `printCsLensType`, `printSi0x000e`, `canonEv`, etc.) — every one uses safe `Value` accessor methods (`toInt64()`, `toUint32()`, `count()`, `size()`, `toString()`) with explicit count checks before access. No raw buffer pointers, no DataBuf allocations, no memcpy, no recursion.

These files are "formatter" code that receives already-parsed `Value` objects from the TIFF/IFD layer and pretty-prints them. All potential memory-safety issues in exiv2 live upstream in `tiffvisitor.cpp`, `tiffcomposite.cpp`, `jpgimage.cpp`, etc. — not here.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
