I've completed a thorough multi-pass analysis of `/data/ylwang/non-textfuzz/target/exiv2/include/exiv2/preview.hpp` and its full implementation in `preview.cpp` (1076 lines), tracing every data-flow path including:

- `LoaderTiff` strip accumulation (`size_ += pos->toUint32(i)` at line 658–660): no overflow possible on 64-bit (max sum ~2^48 << 2^64); on 32-bit, subsequent `Safe::add(idxBuf, size) <= size_` enforce in `getData()` catches it before any OOB write.
- `LoaderExifJpeg` base-offset addition (line 486): plain `size_t +=`, followed by `Safe::add(offset_, size_) > io.size()` guard; no OOB on 64-bit.
- `decodeBase64` / `decodeHex`: both validated for integer overflow and destination-buffer bounds; `destPos` provably never exceeds `destSize`.
- `decodeAi7Thumbnail`: the raw `destData[destPos++]` writes are gated by `Internal::enforce(expectedSize - destPos >= num*3, ...)` before each group; `destPos` is monotonically bounded at `[0, expectedSize]`.
- `Photoshop::locateIrb` psSize byte-overflow (255+1→0): causes a logic/data-confusion bug, but `locateIrb`'s own `dataSize > (sizePsData - position)` check and preview.cpp's `enforce(sizeData >= 28)` keep all returned pointer+length pairs within `psData` bounds.
- `DataBuf::write_uint8` / `read_uint8`: bounds-checked and throw `std::out_of_range` on OOB, not silently corrupt.
- `Safe::add` throughout: throws `std::overflow_error` on overflow for all relevant types on GCC/Clang 64-bit.

No externally-triggerable OOB read/write, heap overflow, UAF, or stack overflow was found.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
