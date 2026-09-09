Having read all 515 lines across three batches and investigated every key call chain:

- **CBS range validation (`cbs_read_unsigned`)**: All parsed fields—`sps_chroma_format_idc` (enforced 0–3), `sps_log2_max_pic_order_cnt_lsb_minus4` (enforced 0–12), `ph_pic_parameter_set_id` (enforced 0–`VVC_MAX_PPS_COUNT-1`), `pps_seq_parameter_set_id` (4-bit = 0–15, within `VVC_MAX_SPS_COUNT=16`)—are range-checked by CBS and return `AVERROR_INVALIDDATA` on violation before reaching parser code.
- **Array accesses in `get_format()` and `set_parser_ctx()`** using `sps_chroma_format_idc` as index: safe, because CBS enforces 0–3.
- **PPS/SPS lookups in `get_pu_info()`**: arrays sized 64 and 16 respectively; indices validated to fit those sizes by CBS.
- **Conformance window subtraction in `set_parser_ctx()`**: CBS validates `sub_width_c*(left+right) < pic_width` before storing, ensuring `s->width` is positive.
- **`append_au()` / `av_grow_packet()`**: overflow is caught by `av_grow_packet`'s internal size check.
- **`buf[i]` read at line 115 in `find_frame_end()`**: `i < buf_size` is the loop invariant; access is in-bounds.
- **`poc_msb` arithmetic in `get_slice_poc()`**: signed overflow UB, but result only feeds POC comparison logic—no memory allocation depends on it.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
