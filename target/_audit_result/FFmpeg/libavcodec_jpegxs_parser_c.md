After reading the complete 252-line file and examining all referenced headers (`bytestream.h`, `get_bits.h`, `jpegxs.h`, `parser.c`), here is my analysis:

**Group 1 – `jpegxs_find_frame_end` (lines 37-100):** Pure state machine; only writes to `pc->frame_start_found`, `pc->state`, `jpegxs->eoc_found`. No heap allocation, no array indexing.

**Group 2 – `jpegxs_parse_frame` (lines 102-212):**
- All `bytestream2_get_be16/byte` calls are bounds-checked (returns 0 on underflow per the `DEF` macro at bytestream.h:72-78).
- All `bytestream2_skip` calls use `FFMIN(buffer_end - buffer, size)` internally — cannot advance past `buffer_end`.
- `components` is validated to be 1 or 3 (line 145-146) before being used as loop bound; arrays `bpc[3]`, `log2_chroma_w[3]`, `log2_chroma_h[3]` are all size-3, so no OOB.
- `init_get_bits8(&gb, gbc.buffer, FFMIN(FFMAX(size-2,0), bytes_left))` — the byte size is clamped to actual available bytes. Any `UPDATE_CACHE` overread by up to 8 bytes lands in the guaranteed `AV_INPUT_BUFFER_PADDING_SIZE` (≥64 bytes) padding that FFmpeg mandates on all AVPacket data and that `ff_combine_frame` enforces (parser.c:249).
- No heap allocations anywhere in the file.

**Group 3 – `jpegxsvideo_parse` / `jpegxsparse_close` (lines 214-244):** Trivial delegation; `av_freep` is always safe.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
