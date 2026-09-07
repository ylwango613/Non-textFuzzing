**Analysis summary across all code sections:**

**Section 1 (lines 1-354) — `jpg_decode()`:**
- Line 269: `jas_safe_size_mul3(image_width, image_height, num_components)` guards total sample count — safe.
- Line 297: `jas_matrix_create(1, cinfo.output_width)` — matrix sized to `output_width`.
- Line 306: `cinfo.output_width * cinfo.output_components` — both are bounded by libjpeg limits (JPEG max dim ≈65535, max components ≤10); product ≤655350, no 32-bit overflow possible.
- Lines 259-261: missing `goto error` when `jpeg_read_header` returns non-OK, but libjpeg still populates fields with safe defaults; no memory corruption path.

**Section 2 (lines 360-413) — `jpg_mkimage()`:**
- Line 384: `cmptparm.width = cinfo->image_width` — image component width set from `image_width`.
- Lines 376-378: bounds check against `JAS_IMAGE_COORD_MAX` before use.

**Section 3 (lines 438-489) — `jpg_put_pixel_rows()`:**
- Line 463: `assert(output_components == numcmpts(image))` — only an assert, not a hard check. In NDEBUG builds this is compiled away.
- Line 466: `width = jas_image_cmptwidth(image, cmptno)` returns `image_width` (set in `jpg_mkimage`).
- Line 469: `jas_matrix_set(data, 0, x, ...)` is a raw macro with zero bounds checking. Matrix has `output_width` columns, loop uses `image_width` as bound.

**Critical question: can `image_width != output_width`?**  
`output_width` is computed by `jpeg_start_decompress()` as `jdiv_round_up(image_width * scale_num, scale_denom)`. Since no scaling is requested (code never sets `cinfo.scale_num/scale_denom`), defaults are 1/1, giving `output_width = image_width` exactly. No crafted file can change this independently — libjpeg enforces the equality.

**bufptr access range:** for `cmptno ∈ [0, output_components-1]` and `x ∈ [0, output_width-1]`, max index = `(output_components-1) + (output_width-1)*output_components = output_width*output_components - 1` — exactly within the `alloc_sarray`-allocated buffer.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
