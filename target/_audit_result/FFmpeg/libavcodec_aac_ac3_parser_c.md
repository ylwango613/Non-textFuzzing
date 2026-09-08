After thorough analysis of `aac_ac3_parser.c` (173 lines), its direct callees (`ac3_parser.c`, `parser.c`), and all related headers, here are my findings:

**Boundary checks reviewed:**
- `buf[i]` accesses are all guarded by `i < buf_size` (line 57 loop)
- `hdr.frame_size <= buf_size` is checked before CRC call (line 112)
- `ff_ac3_find_syncword`'s potential `buf[i+1]` read at even `buf_size` — reads into the mandatory `AV_INPUT_BUFFER_PADDING_SIZE` zero padding that `ff_combine_frame` allocates; not exploitable
- `s->remaining_size` arithmetic: minimum AC3/EAC3 frame_size = `AC3_HEADER_SIZE = 7`; subtracting at most `header_size - 1 = 6` keeps it non-negative
- `ff_combine_frame`'s `next + AV_INPUT_BUFFER_PADDING_SIZE` memcpy size is guarded by `if (next > -AV_INPUT_BUFFER_PADDING_SIZE)`
- `avpriv_ac3_parse_header(&phrd, ...)` with stack-allocated `phrd = &hdr` (non-NULL) skips the malloc path; no memory leak or UAF
- `s->frame_number` is pre-incremented before division; no divide-by-zero

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
