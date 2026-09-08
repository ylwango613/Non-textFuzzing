Having read the complete implementation (`orfimage_int.hpp` + `orfimage_int.cpp` + `orfimage.cpp`) and traced every data path:

- `OrfHeader::read()`: the `size < 8` guard fires before any byte access; `getUShort(pData+2,…)` and `getULong(pData+4,…)` both fall within the validated 8-byte window.
- The file-controlled IFD offset stored by `setOffset()` is immediately bounded at `TiffParserWorker::parse()` line 2121: `pHeader->offset() >= size` throws before the pointer arithmetic.
- `OrfHeader::write()`: all `DataBuf::write_uint{8,16,32}` helpers throw `std::out_of_range` on OOB access; the 8-byte buffer is sized to accommodate every write (`write_uint8` at 0 and 1, `write_uint16` at 2, `write_uint32` at 4).
- The inverted condition `if (0 == orfHeader.read(pData, 8))` at `orfimage.cpp:103` is a logic bug (byte-order may be wrong) but cannot cause memory corruption.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
