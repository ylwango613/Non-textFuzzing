Complete analysis done. The file is 409 lines, fully read in one pass.

**Analysis summary:**

- **Line 319**: `decoded_subtitle_size = parsed_data_size * 4` — potential `size_t` multiplication overflow on 32-bit, but the wrapped value is then passed *as the size limit* to `arib_decode_buffer()`, so no OOB write in FFmpeg code results.
- **Line 269**: `av_bprint_append_data(&buf, region->p_start, region_length)` — `region_length` is `ptrdiff_t` narrowed to `unsigned`, but `region_length < 0` is caught at line 234–238 before this point, and `av_bprint` with `AV_BPRINT_SIZE_UNLIMITED` grows dynamically without overflow.
- **`av_mallocz(decoded_subtitle_size + 1)`**: Only reaches this if `!parsed_data || !parsed_data_size` passes (line 312); no feasible integer overflow path to under-allocate then over-write.
- **`arib_decoder_get_regions()` pointer subtraction**: Negative length is caught and returned as `AVERROR_INVALIDDATA`.
- **No raw `memcpy`/`memmove` with unchecked user-controlled sizes**.
- All `arib_*` external library call sizes are bounded by internal-to-library accounting — library bugs are out of FFmpeg's scope.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
