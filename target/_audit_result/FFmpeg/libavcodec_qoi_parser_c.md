**Analysis complete.**

- `qoi_parser.c` is 79 lines. The entire logic is: iterate `buf[i]` (0 ≤ i < buf_size, no OOB), maintain a `uint64_t` state machine (no overflow possible on unsigned 64-bit shifts), detect the QOI 8-byte end-of-stream marker (`0x00×7 ‖ 0x01`), then delegate to `ff_combine_frame`.
- `ff_combine_frame` (parser.c): The `*buf_size + pc->index + AV_INPUT_BUFFER_PADDING_SIZE` size arithmetic is `int+int+int` and could theoretically overflow, but `av_fast_realloc` takes `size_t`, the buffer grows via successful heap allocations over many calls, and reaching near-INT_MAX accumulation (≈2 GB) before allocation failure is not a realistic attack path through the QOI parser.
- No direct allocations, memcpy, or unchecked index arithmetic exist in `qoi_parser.c` itself.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
