I now have complete context. Let me verify the arithmetic bound mathematically:

- `ff_set_dimensions` calls `av_image_check_size2(w, h, max_pixels, AV_PIX_FMT_NONE, ...)`.
- With `AV_PIX_FMT_NONE`, `av_image_get_linesize` returns ≤0 so `stride = 8LL*w + 1024`.
- The guard `stride*(h + 128ULL) >= INT_MAX` must be false, so `(8w+1024)*(h+128) < 2^31`.
- This implies `8*w*h < 2^31`, i.e., `w*h < 268,435,456`.
- Therefore `width * height * (bpp>>3)` at line 138 is at most ~536M for bpp=16, well within int32, so no overflow.
- All unchecked bytestream reads (`bytestream2_get_byteu` / `bytestream2_get_be16u`) are guarded by that pre-checked condition.
- `pgx_get_number` correctly caps each parsed value at INT_MAX via `uint64_t` accumulation.
- Shift amounts in WRITE_FRAME are bounded 0–7 for bpp=16 and 0–7 for bpp=8; no UB.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
