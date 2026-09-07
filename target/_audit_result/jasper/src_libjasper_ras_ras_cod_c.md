After exhaustively reading all relevant files (`ras_cod.c`, `ras_dec.c`, `ras_cod.h`, `jas_seq.c`, `jas_malloc.c`, `jas_math.h`) and tracing every data-controlled value through the decoder, I can summarize the findings across each attack surface:

**`ras_getdatastd`**: `x` and `y` loop variables are `int`; they could in theory wrap if `hdr.width`/`hdr.height` exceed `INT_MAX`. However, the `jas_safe_size_mul3` + `max_samples` guard (64 × 1 MiB = 67 108 864) rejects any image whose total samples would overflow before the loop is entered, ensuring both dimensions stay well within `INT_MAX`.

**`RAS_ROWSIZE` overflow**: `width × depth` is computed in `int_fast32_t` (int64_t on LP64); with `max_samples` capping the product `width × height × ceil(depth/8)`, the maximum reachable `width × depth` value is far below int64_t overflow. `hdr.length` for `RAS_TYPE_OLD` is informational only—never passed to `malloc`.

**`ras_getcmap` colormap bounds**: `numcolors = 1 << depth` is UB for depth 31–32, but the surrounding logic (negative/zero result fails `> RAS_CMAP_MAXSIZ` guard with a logical return -1) prevents any array out-of-bounds write. For valid depth ≤ 8, `numcolors ≤ 256 = RAS_CMAP_MAXSIZ`, and `actualnumcolors = maplength/3 ≤ numcolors` keeps all `cmap->data[j]` writes within the statically declared `int data[256]`.

**`jas_matrix_create` / `jas_alloc2`**: Both use `jas_safe_size_mul` before every `malloc`, returning NULL on overflow; callers check for NULL.

**`pad` calculation**: Always 0 or 1; only one padding byte is conditionally consumed. No underflow or overread possible.

**`ras_getcmap` with `maptype == RAS_MT_NONE`**: Non-zero `maplength` causes stream misalignment for subsequent pixel reads—a logic/correctness issue, not a memory-safety issue.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
