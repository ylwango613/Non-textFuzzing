After exhaustive analysis spanning all 691 lines of `types.cpp` in multiple batches, plus deep tracing into key callers (`tiffvisitor_int.cpp`, `tiffimage_int.cpp`, `tiffcomposite_int.cpp`, `value.hpp`, `bmffimage.cpp`, `rafimage.cpp`, `crwimage_int.cpp`, `iptc.cpp`), my findings are:

**Batch 1 (lines 1-200):** All `DataBuf` methods (`read_uint8/16/32/64`, `write_uint8/16/32/64`, `cmpBytes`, `c_data`) have correct bounds checking. The only design quirk: `c_data()` silently returns `nullptr` when the buffer is empty regardless of offset (instead of throwing for non-zero offsets), but callers use the bounds-checked read methods before obtaining raw pointers.

**Batch 2 (lines 200-400):** Raw-pointer helpers (`getULong`, `getLong`, `getShort`, `getURational`, etc.) have no internal bounds checking by design; all call-site validations (tiffvisitor_int.cpp line 1236: `p + 12 > pLast_` guard; rafimage.cpp: 4-byte stack arrays read via `io_->readOrThrow`; crwimage_int.cpp line 176: `enforce(size >= 10 && start <= size - 10, ...)`) are correct. Signed left-shift UB in `getULong` (`buf[3] << 24` when buf[3] ≥ 0x80) is technically UB but produces the correct bit pattern on all two's-complement targets.

**Batch 3 (lines 400-691):** Arithmetic functions (`floatToRationalCast`, `parseInt64`, `parseFloat`, `parseRational`) are safe. Integer overflow check in `readTiffEntry` (`count > SIZE_MAX / typeSize → throw`) prevents heap under-allocation. `makeSlice` properly validates `end ≤ buf.size()` and the Slice constructor enforces `begin < end`.

**Key callers verified clean:**
- IPTC `sizeData` is validated before use (line 402).
- BMFF `buffer_size` cast to `size_t` is guarded by prior enforce against file size.
- `strips_.size() * 4` in `TiffImageEntry::doWrite` cannot overflow because `strips_.size()` is bounded by `count ≤ SIZE_MAX/typeSize` from `readTiffEntry`.
- Integer overflow in `ValueType<T>::read` is prevented because `len` passed in was already checked for `count * typeSize ≤ SIZE_MAX`.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
