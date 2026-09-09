All arithmetic edge cases are correctly caught. After thorough multi-pass analysis:

- **`rv10_build_vlc`**: All input is static compile-time data; `nb_syms` = 1023 = `MAX_VLC_ENTRIES` exactly, no OOB writes.
- **`rv10_decode_frame` slice parsing**: Slice offsets validated via `offset >= buf_size` check; size computed as `get_slice_offset(i+1) - offset` — any negative/wrapping result is caught by `size <= 0`; and the final `offset + FFMAX(size, size2) > buf_size` check prevents any OOB buffer access.
- **`rv20_decode_picture_header`**: `rpr_max` is limited to 3 bits (0–7); `f` from bitstream is bounded by `rpr_bits ≤ 3` giving at most 7; extradata bounds checked (`extradata_size < 8 + 2 * f`) before any `extradata[6 + 2*f]` / `extradata[7 + 2*f]` access.
- **`rv10_decode_init`**: `extradata_size < 8` guard before all `extradata[1..7]` accesses.
- **`rv10_decode_packet`**: `mb_x`/`mb_y` from bitstream are validated against `mb_width`/`mb_height` before use.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
