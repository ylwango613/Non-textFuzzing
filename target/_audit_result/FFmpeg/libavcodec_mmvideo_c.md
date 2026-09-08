The bytestream2 implementation at line 74-76 confirms: on underread it sets `g->buffer = g->buffer_end` and returns 0 — so in `mm_decode_inter`, when the control data is exhausted, `g->buffer` advances to `buffer_end = data_ptr.buffer_start`, making the while condition false and terminating the loop correctly.

The avcodec.c:241-246 global check confirms: any dimensions that would cause `width * height` to overflow are caught by `av_image_check_size2` in `avcodec_open2`, zeroing out the dimensions before `mm_decode_init` even runs, so the check in `mm_decode_raw` is never exposed to overflow-prone values.

**Analysis summary across all functions:**

- **mm_decode_raw** (line 80-87): The `width * height` size check could theoretically overflow, but `avcodec_open2` pre-validates dimensions with `av_image_check_size2`, rejecting any combination that overflows. Unreachable overflow path.
- **mm_decode_pal** (line 89-95): Palette index `(start+i)&0xFF` is always 0–255, bounded against the 256-entry array. Bytestream2 underreads return 0 safely.
- **mm_decode_intra** (line 101-139): `run_length` after doubling is at most 258; the check `run_length > width - x` guards both the primary and the `half_vert` memset rows. `y` is checked before each row write. No OOB path found.
- **mm_decode_inter** (line 145-194): `x` is bounded by `x + half_horiz >= width` before any frame write. `y` is bounded by `y + half_vert >= height` before the inner loop. The bytestream2 buffer-end sentinel terminates the while loop correctly on exhaustion. No OOB path found.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
