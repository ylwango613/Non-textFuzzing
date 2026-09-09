After a complete, multi-pass audit of `pnm_parser.c` and its full call chain — `ff_pnm_decode_header` in `pnm.c`, `ff_combine_frame` in `parser.c`, and `av_image_get_buffer_size`/`av_image_check_size` in `libavutil/imgutils.c` — the analysis covers:

1. **Buffer size arithmetic (line 113–119)**: `av_image_get_buffer_size` internally re-validates dimensions via `av_image_check_size2` (stride×(h+128) < INT_MAX), and the result is guarded by the `next + (uint64_t)ret <= INT_MAX` check before `next` is updated — no overflow path.

2. **`bytestream_end = buf + buf_size - skip` (line 70)**: Technically undersizes the range when skip > 0, but only makes the accessible window *smaller*, never permitting a read past `buf + buf_size`. The length check in `ff_pnm_decode_header` always fires before any dereference when bytestream ≥ bytestream_end.

3. **`ascii_scan` management**: Always computed as `sync − bytestream + skip ≥ 0`; enforced against `pc->index` by `av_assert0` at line 90 on every re-entry — no heap advance beyond the accumulated buffer.

4. **`remaining_bytes` (line 123)**: `next − buf_size` where `next ≤ INT_MAX` (overflow guard) and `buf_size ≥ 0`; decremented by `FFMIN(remaining, buf_size)` — no wrap-around.

5. **YUV420P height × 2 (pnm.c:239)**: `av_image_check_size2`'s `stride×(h+128) < INT_MAX` constraint caps practical height at ~2M (for w=1), so `h×2` cannot overflow int.

6. **`ff_combine_frame` overread/memmove**: All source and destination ranges fall within the previously `av_fast_realloc`-sized buffer; `memmove` on overlapping regions is safe.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
