After thorough multi-pass analysis of `h264_refs.c` and its call chain (including `h264_parse.c`, `h264_ps.c`, and `h264dec.h`), I have verified the following bounds for all critical arrays:

- `ref_list[2][48]`: populated by `build_def_list`; in field mode max total entries = 2 × (short_ref_count + long_ref_count) ≤ 2×16 = 32 ≤ 48.
- `ref_modifications[2][32]`: bounded by `ref_count[list] ≤ 32` (field mode) validated in `ff_h264_parse_ref_count`.
- `h264_fill_mbaff_ref_list`: in MBAFF (frame-picture) mode, `ref_count[list] ≤ 16`; max index = 16+2×15+1 = 47, exactly within bounds.
- `short_ref[32]` / memmove: `short_ref_count` bounded to ≤ `ref_frame_count ≤ H264_MAX_DPB_FRAMES (16)` by SPS validation + DPB overflow guard at line 769.
- `long_ref[32]`: `long_arg` for all MMCO ops validated ≤ 15 (or halved by `pic_num_extract` for field ops).

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
