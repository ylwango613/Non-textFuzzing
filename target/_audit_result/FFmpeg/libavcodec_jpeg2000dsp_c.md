After thorough analysis of `jpeg2000dsp.c` (all 105 lines), its header `jpeg2000dsp.h`, related headers (`jpeg2000.h`, `jpeg2000dwt.h`), the calling context in `jpeg2000dec.c:mct_decode()`, and the allocation site in `jpeg2000.c:ff_jpeg2000_init_component()`:

**Summary of analysis:**

- `ict_float`, `ict_int`, `rct_int`: Pure in-place arithmetic transforms iterating `csize` times over three caller-provided buffers. No internal allocations, no index arithmetic beyond pointer increments.

- `csize` consistency: Both the allocation in `ff_jpeg2000_init_component` (`uint32_t csize = width * height`) and the call-site computation in `mct_decode` (`int csize = coord_diff_x * coord_diff_y`) use the same `tile->comp[0].coord` fields — they match.

- Bounds: `av_image_check_size` + explicit `> 32768` per-dimension check in `ff_jpeg2000_init_component` cap the maximum product at 32768×32768 = 1,073,741,824, which fits safely in both `uint32_t` and `int`.

- Invalid `transform` (> 2): `ff_jpeg2000_dwt_init` returns `-1` (default branch) for any transform value outside {0,1,2}, which propagates as an error through `ff_jpeg2000_init_component`, aborting tile setup before `mct_decode` is ever reached.

- Type consistency: `mct_decode` correctly selects `f_data` (float) for `FF_DWT97` → `ict_float`, and `i_data` (int32_t) for `FF_DWT53`/`FF_DWT97_INT` → `rct_int`/`ict_int`. No type confusion.

- Arithmetic overflow in pixel value computations (e.g., `2 * *src1`, signed addition in `ict_int`) is intentional fixed-point arithmetic affecting pixel values only — not memory addresses or buffer sizes.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
