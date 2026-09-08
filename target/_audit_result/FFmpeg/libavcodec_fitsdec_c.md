After thorough analysis of `fitsdec.c`, `fits.c`, and `fits.h`:

**Key findings examined:**

1. **`naxisn[999]` OOB**: `naxis_index` can reach at most 998 (writing `naxisn[998]`) because FITS keywords are limited to 8 characters — `NAXIS999` (8 chars, valid) is the maximum representable NAXISn keyword. `NAXIS1000` (9 chars) cannot fit, so `naxis_index >= 999` never occurs in practice. No OOB write possible.

2. **Size computation in `fits_read_header` (lines 145–155)**: The overflow check `header->naxisn[i] > SIZE_MAX / size` is correctly guarded before the multiplication. Negative `naxisn` values convert to a huge `size_t`, triggering the subsequent `end - ptr8 < size` check which returns `AVERROR_INVALIDDATA`.

3. **`fill_data_min_max` loop bounds**: `end` is passed but never used inside the loops — however, `fits_read_header` validates that `end - ptr8 >= total_image_size` before calling this function, so it's safe.

4. **`CASE_GRAY`/`CASE_RGB` macro loops**: Both iterate exactly `width × height × bytes_per_pixel` bytes, which is validated against packet size before any copying begins. No OOB read possible.

5. **`lrint` result truncation to `uint16_t`/`uint8_t`**: A logical correctness issue (wrong pixel value if `t` is outside `[data_min, data_max]`), but writes always go to the correct destination within the allocated frame buffer. Not a memory-safety bug.

6. **`map[]` array access in CASE_RGB**: `k` ∈ {0,1,2,3}, and `naxisn[2]` is validated to be exactly 3 or 4, so all accesses `map[k]` are within bounds.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
