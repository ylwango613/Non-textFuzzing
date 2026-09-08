The file is only 157 lines and I've now read it completely. Let me confirm the one borderline pattern I noticed in the `DCA_SYNCWORD_CORE_LE` branch — the loop writes `ceil(src_size/2)*2` bytes to dst, which is `src_size+1` when `src_size` is odd:

- `DCA_CORE_FRAME_HEADER_SIZE = 18` (even), so both the dtsdec.c and dca_parser.c callers pass an even-sized buffer — no OOB.
- dca_parser.c allocates `hdr[DCA_CORE_FRAME_HEADER_SIZE + AV_INPUT_BUFFER_PADDING_SIZE]` — additional 64 bytes of headroom.
- dcadec.c uses `av_fast_padded_malloc` which sets `s->buffer_size` to `≥ input_size + AV_INPUT_BUFFER_PADDING_SIZE + extra`, so writes up to `input_size+1` bytes stay well within bounds.

The `ff_dca_parse_core_frame_header` function only reads via GetBitContext (internally bounds-checked); no allocations occur there. The 14-bit conversion path outputs at most 7/8 of max_size, safely within the destination buffer. No integer overflows reach malloc in this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
