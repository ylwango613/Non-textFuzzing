After reading all four relevant files (`bmp_cod.c`, `bmp_dec.c`, `bmp_cod.h`, and the malloc/math utilities) and tracing every code path that handles attacker-controlled input:

**Group 1 – bmp_cod.c (136 lines):** All four functions (`bmp_info_create`, `bmp_info_destroy`, `bmp_isgrayscalepal`, `bmp_numcmpts`) are pure utility code with no direct file-input processing. No allocation-size arithmetic from file data.

**Group 2 – Palette allocation in `bmp_getinfo()` (bmp_dec.c:398-415):** `jas_alloc2(info->numcolors, sizeof(bmp_palent_t))` uses overflow-checked multiplication. The guard `numcolors > 256 && numcolors > num_pixels` combined with the `max_samples = 64M` limit in `bmp_decode()` bounds practical `numcolors` to ≤ 64M entries, well within `int` range, preventing loop-counter signed overflow.

**Group 3 – Loop counter `int i` vs `int_fast32_t numcolors` (bmp_dec.c:407):** On 64-bit Linux, `int_fast32_t = long` (64-bit). The counter `i (int)` could overflow when `numcolors > INT_MAX`. However, the prerequisite allocation of `> 2.1B` entries × 8 bytes ≈ 17 GB would fail, gating the loop entirely.

**Group 4 – `bmp_getdata()` arithmetic:** `numpad = (numcmpts * info->width) % 4` is evaluated as `int × long = long`; result [0,3] fits in `int`. Matrix creation uses `jas_safe_size_mul`. `jas_matrix_setv` accesses indices `[0, info->width-1]` in a matrix dimensioned to exactly `info->width` columns.

**Group 5 – `bmp_isgrayscalepal` type truncation:** `numcolors` is truncated `long → int` at the call site; if negative after truncation, the loop exits immediately — no OOB.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
