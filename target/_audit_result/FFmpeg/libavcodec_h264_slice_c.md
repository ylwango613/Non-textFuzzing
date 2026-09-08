After reading all 2957 lines of the file in 6 batches and cross-referencing related headers, the SEI parsing code, the PS (parameter set) parsing with its `av_image_check_size` guards, and the ref2frm array layout, here is my conclusion:

- `alloc_scratch_buffers()` (lines 130–160): `alloc_size` and all derived pool sizes are bounded by the validated `mb_width`/`mb_height` via `av_image_check_size` upstream in `h264_ps.c:464–468`.
- `init_table_pools()` (lines 162–186): `big_mb_num`, `b4_array_size` all constrained by same guard; no integer overflow.
- `h264_export_frame_props()` timecode (lines 1282–1307): `timecode_cnt` is max 3 (`sei_num_clock_ts_table` max = 3), buffer holds 4 × `uint32_t`; access `tc_sd[1..3]` — within bounds.
- `ref2frm[]` access in `fill_filter_caches_inter()` (lines 2329–2384): `ref_count` is capped at 16 for PICT_FRAME by `ff_h264_parse_ref_count()`; MBAFF max field index = 2×16−1 = 31; with offset 20 → absolute index max = 51 < 64.
- `backup_mb_border()` AV_COPY128 calls: `top_borders` allocated as `mb_width × 96 bytes`; `mb_x ∈ [0, mb_width−1]` enforced by bounds check at line 1948–1952.
- QP parsing with unsigned cast (lines 1886–1890): overflow wraps to a large unsigned value that always fails the `> 51` check → `AVERROR_INVALIDDATA`.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
