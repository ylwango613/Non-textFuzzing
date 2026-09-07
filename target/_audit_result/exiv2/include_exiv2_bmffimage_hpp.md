I have now completed a thorough, multi-pass analysis of `bmffimage.hpp` and its full implementation in `bmffimage.cpp`. Let me summarize the key findings from each code region before issuing the final verdict.

**Batch 1 (lines 1–500): boxHandler header parsing, iloc, iinf, colr, uuid**
- `hdrbuf` is a fixed 8-byte stack array read exactly with `io_->read`. Safe.
- `iloc` step computation: `(static_cast<size_t>(box_length) - 16) / itemCount` — potential unsigned underflow when `box_length < 16`, but the guard condition `itemCount < box_length / 14` (which requires `box_length / 14 > 1`, i.e. `box_length >= 28`) makes the branch unreachable for small values. The broken `enforce(data.size() - skip >= step)` when `skip > data.size()` would underflow to SIZE_MAX, silently passing — but subsequent `data.read_uint32(skip, ...)` still throws `std::out_of_range` due to DataBuf bounds checking.
- `parseCr3Preview` is called without a preceding enforce on `data.size()` being sufficient for the width/height/size reads — but `DataBuf::read_uint16/32` check bounds and throw `std::out_of_range` before any OOB memory access.

**Batch 2 (lines 500–800): brob, parseTiff, parseXmp, readMetadata**
- `brob` case (line 537): `arr.read_uint32(0, endian_)` is called on the brotli-decompressed buffer without first checking `arr.size() >= 4`. If decompressed output is < 4 bytes, `read_uint32` throws `std::out_of_range` (uncaught — DoS but not memory corruption).
- `parseXmp`: `DataBuf xmp(lengthSizeT + 1)` — integer wraparound if `lengthSizeT == SIZE_MAX`, but `enforce(length <= io_->size() - start)` bounds `length` to file size, making this practically unreachable.
- `parseTiff` two-arg: `for (size_t i = 0; i < exif.size() - 9 ...)` — potential unsigned underflow, but guarded by `if (exif.size() > 8)`.
- `brotliUncompress`: `compressedBufSize * 2` overflow — would require a ~8 exabyte file; practically unreachable.
- `readMetadata` loop: `address = boxHandler(...)` always returns a strictly larger value, so no infinite loop.

**DataBuf bounds checking (verified from types.cpp):**
All `read_uint8/16/32/64` functions throw `std::out_of_range` on any out-of-bounds access. `c_data(offset)` throws for `offset > size()`, returns `nullptr` only for `offset == size()`. These checks consistently prevent memory corruption across all code paths.

**Recursion / loop bounding:**
- `depth >= max_recursion_depth_` in `boxHandler` hard-limits recursion depth.
- `visits_.size() > visits_max_` (= `io_->size() / 16`) caps total box visits.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
