After thorough analysis of `png.c` (64 lines), its header `png.h`, and all call-sites in `pngdec.c` and `pngdsp.c`, I traced every data-flow from untrusted input to memory operations:

**`ff_png_pass_row_size` integer overflow check:**
- `pass_width * bits_per_pixel` could theoretically overflow 32-bit int when `width` is large. However, `av_image_check_size` at IHDR parsing time bounds `width` such that `stride * (height + 128) < INT_MAX` using `stride = 8*width`. This limits `width` (for height=1) to ≈2 million pixels. With `bits_per_pixel ≤ 64`, the product is at most ≈128 million — well within `int` range. The overflow path is unreachable.

**`row_size` overflow (pngdec.c:918):**
- `s->row_size = (s->cur_w * s->bits_per_pixel + 7) >> 3`: same constraint applies — `av_image_check_size` bounds `cur_w` before this computation, preventing overflow.

**`pass_row_size` vs `buffer` size mismatch (interlaced path):**
- `buffer` is allocated as `row_size + 16`, and `crow_size = pass_row_size + 1`. Since `pass_row_size ≤ row_size` for all passes (pass 6 is the only one equal to full width), the buffer is always sufficient.

**Array index bounds on `pass`:**
- `ff_png_pass_xmin[pass]` and `ff_png_pass_xshift[pass]` are guarded: callers only increment `s->pass` after checking `s->pass == NB_PASSES - 1` as the termination condition, so `pass` ∈ [0, 6] = [0, NB_PASSES-1] always.

**`bpp=0` with transparency flag:**
- When grayscale 8-bit image has transparency, `bpp` is temporarily decremented to 0. In `ff_png_filter_row`, this causes logical errors (self-referential filter computation) but no out-of-bounds memory access.

**Unvalidated `filter_type` byte:**
- `crow_buf[0]` (per-row filter type) is not range-checked before passing to `ff_png_filter_row`. An invalid value (e.g., 5–255) causes the `switch` to fall through silently — logic bug, no memory corruption.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
