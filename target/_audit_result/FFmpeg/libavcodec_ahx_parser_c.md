I have now completed full analysis of `ahx_parser.c` and traced every execution path through `ff_combine_frame`.

**Analysis summary:**

- The file is 79 lines. `ahx_parse` uses a 4-byte sliding window to detect the AHX sync header, then calls `ff_combine_frame` with `next = i - 3` (which can be negative when `i < 3`).

- For `next = i - 3 < 0` to be reachable, `s->size > 4` must hold at position `i < 3` of the current call, which requires `s->size_accumulated >= 4 - i` bytes from prior END_NOT_FOUND calls. Those prior calls necessarily buffered those bytes into `pc->buffer`, so `pc->index >= s->size_accumulated >= |next|`. Therefore `pc->last_index + next >= 0` always holds in the overread loop — no OOB.

- `*buf_size = pc->index + next` is non-negative by the same invariant (minimum 0 when `pc->index == |next|`), so no negative size is forwarded to the decoder.

- `s->size` (int) increments unboundedly but wrapping after 2 GB of no-sync data is a theoretical DoS with no memory corruption consequence.

- `s->header = 0` (stream starts with 4 zero bytes) causes repeated false matches but no memory corruption.

No exploitable memory-safety vulnerability is present in this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
