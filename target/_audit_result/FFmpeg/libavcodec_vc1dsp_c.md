After fully reviewing the file in two passes (lines 0-600 and 600-1045), tracing all key callsites in `vc1_common.h`, `vc1_loopfilter.c`, and `vc1dec.c`, and verifying the following:

- **IDCT functions** (`vc1_inv_trans_8x8_c`, etc.): all array accesses bounded to fixed 64-element blocks; intermediate values fit in `int32`.
- **Overlap transforms** (`vc1_v_s_overlap_c`, `vc1_h_s_overlap_c`): blocks stored as `int16_t[6][64]` per MB; stride-16 field-mode accesses reach at most index 247 within the 384-element allocation.
- **Loop filter** (`vc1_filter_line`, `vc1_loop_filter`): context pixel accesses are standard codec assumptions, not attacker-controlled distances.
- **MSPEL MC** (`vc1_mspel_mc`/`_mc_16`): temp buffers `int16_t[88]` and `int16_t[304]` are exactly correctly sized for their iteration counts; no OOB.
- **Chroma MC** (`put_no_rnd_vc1_chroma_mc8_c`, etc.): loops bounded by `h` which is set by the decoder; no allocation here.
- **`sprite_h_c`**: `sprite_width ≤ 1<<14` is validated; `sr_rows` allocated as `output_width` bytes; the single `src[(offset>>16)+1]` read at the last iteration lands within FFmpeg's standard `AV_INPUT_BUFFER_PADDING_SIZE` frame buffer padding.
- **`vc1_unescape_buffer`**: writes at most `size` bytes to `dst`; all callers allocate `size + AV_INPUT_BUFFER_PADDING_SIZE` bytes for `dst`.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
