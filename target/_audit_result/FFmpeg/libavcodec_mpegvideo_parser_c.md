Having read the complete 310-line file and traced into `ff_set_dimensions`, `ff_combine_frame`, `ParseContext`, and the `FFALIGN` macro, I can now render a final verdict.

Key findings from the full analysis:

- **`mpeg1_find_frame_end`**: All `buf[i]` accesses are within the `i < buf_size` loop guard; `avpriv_find_start_code` receives valid pointer range `[buf+i, buf+buf_size]`.
- **Width/height extraction**: In `SEQ_START_CODE` the fields are 12-bit values (max 4095); after the `EXT_START_CODE` sequence extension, `horiz_size_ext` is a 2-bit field giving `pc->width` ≤ `0x3FFF = 16383`. All buffer reads are guarded by `bytes_left >= N`.
- **`FFALIGN(pc->width, 16)`**: `FFALIGN(16383, 16) = 16384`, well within `int` range, no overflow.
- **`ff_set_dimensions`**: validates via `av_image_check_size2`; zeroes dimensions on failure, safely handles the bounded inputs.
- **No heap allocations** in this file — the parser itself uses `ff_combine_frame` (in `parser.c`) which employs `av_fast_realloc` with proper size tracking.
- All switch/case paths that read from `buf` first confirm `bytes_left >= required_bytes`.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
