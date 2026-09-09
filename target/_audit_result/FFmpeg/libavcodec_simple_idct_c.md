After reading `simple_idct.c` in full (233 lines) and its included template `simple_idct_template.c`, plus checking call sites and the header:

**Analysis summary:**

- The entire file is a pure mathematical IDCT implementation operating on **fixed-size 8×8 DCT blocks** (64 `int16_t` = 128 bytes). No dynamic allocation (`malloc`/`av_malloc`/`av_realloc`) exists anywhere in the file.
- All array accesses use **compile-time constant offsets**: `col[8*0]` through `col[8*7]` (indices 0–56), `row[0]` through `row[7]`, `block + i*8` for i ∈ 0..7 — every access stays within the 64-element fixed block.
- `block + i` (i ∈ 0..7) passed to `idct4col_put`/`idct4col_add` accesses at most `block[7 + 8*6]` = `block[55]` < `block[64]`. Likewise `block + 8 + i` reaches at most `block[63]`.
- There are no `memcpy`, `strcpy`, `sprintf`, or similar length-driven copy operations.
- Integer arithmetic uses `SUINT` (unsigned) to avoid UB on overflow, and results are clamped via `av_clip_uint8`/`av_clip_pixel` — no overflow propagates to an out-of-bounds access.
- The `line_size`/`dest` parameters are frame-level values set by the codec allocator, not directly from container bytes, and even with adversarial `line_size` values, the writes are single `uint8_t` stores with no compounding buffer size.
- No externally-controlled field (chunk size, nb_entries, extradata_size, etc.) feeds any buffer operation in this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
