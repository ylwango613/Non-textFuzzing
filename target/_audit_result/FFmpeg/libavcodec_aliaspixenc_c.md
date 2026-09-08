`ff_alloc_packet` takes `int64_t size` and explicitly rejects `size < 0` (line 64). With the overflow analysis:

- If `width = height = 65535` (both pass `> 65535`), `width * height` overflows signed int32 to `-131071`, bypassing the check.
- Then `4 * width * height` in `length` also overflows to approximately `-524,274`.
- Passed as `int64_t` to `ff_alloc_packet`, the negative value is caught and returns `AVERROR(EINVAL)`.

The RLE loop writes at most `4 * width * height` real bytes (for BGR24 with no compression), exactly matching the allocated `length` when dimensions are valid. The `bytestream_put_*` helpers advance `buf` in-bounds. The allocation path is guarded end-to-end.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
