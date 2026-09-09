The file is only 95 lines and contains two trivial no-op stubs:

- `null_decode()`: sets `*got_frame = 0`, returns `avpkt->size` — no memory access whatsoever.
- `null_encode()`: sets `*got_packet = 0`, returns `0` — no memory access whatsoever.

There are no `av_malloc`/`memcpy`/array-index operations, no parsing of external data, and no integer arithmetic in either function. The codec registrations are static compile-time structs with no runtime allocation.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
