The file is only 58 lines with a single function. I've fully read it and all callers. The analysis is complete:

- `ff_startcode_find_candidate_c` performs no heap allocation, no memcpy, no format strings.
- The fast unaligned path reads 4 or 8 bytes while `i < size` (not `i + 7 < size`), intentionally reading up to 7 bytes past `size`. The inline comment explicitly documents this: callers must supply `AV_INPUT_BUFFER_PADDING_SIZE` bytes of zero-padding beyond the declared size — a contract enforced by `av_packet_new_side_data`/`av_grow_packet` throughout FFmpeg. Both callers (`h264_parser.c:114`, `vc1_parser.c:189`) receive `AVPacket->data` which is always allocated with this padding.
- The return value is a plain byte offset, no pointer arithmetic, no allocation.
- No integer overflow vectors, no out-of-bounds write, no stack buffer, no format string.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
