The scanner's maximum `CACHE` call is `CACHE(parser, 4)`, which means `length` never exceeds 4 across the entire libyaml scanner. With `length = 4`, one raw-buffer decode cycle produces at most 8192 characters (UTF-16 BMP path: 16384/2), which immediately satisfies any `unread < 4` condition. The outer `while (parser->unread < length)` loop executes at most one decode cycle per call, and the buffer sizing invariant (`INPUT_BUFFER_SIZE = 3 × INPUT_RAW_BUFFER_SIZE`) guarantees the decoded output fits with plenty of headroom (at most ~12 leftover bytes + 24576 newly decoded = 24588 ≪ 49152).

No other write to `parser->buffer.last` in the decode path is reachable without passing through that same guardrail. The EOF NUL write (line 358) is similarly unreachable as an overflow because it occurs only after the while-loop exits with `unread ≥ length` — meaning the buffer already has room.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
