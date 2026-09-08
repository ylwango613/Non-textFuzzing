I've now completed thorough analysis of all 185 lines of `/data/ylwang/non-textfuzz/target/FFmpeg/libavcodec/mpeg4video.c` and traced all relevant data structures and allocations.

**Summary of findings per function group:**

- **`ff_mpeg4_clean_buffers` (lines 44–67):** The negative `l_xy` index (`-(b8_stride+1)` when mb_y=mb_x=0) is intentional — `ac_val` is set to `ac_val_base + b8_stride + 1`, so the minimum index maps exactly to `ac_val_base[0]`. No OOB.

- **`ff_mpeg4_init_direct_mv` (lines 73–81):** Writes to `direct_scale_mv[0][0..63]` sequentially — the array is declared `int16_t direct_scale_mv[2][64]`. No OOB. Division by `s->pp_time` is guarded upstream in mpeg4videodec.c (line 3140: `pp_time <= 0` check). `pp_time`/`pb_time` are `uint16_t` fields — no truncation surprise.

- **`ff_mpeg4_set_one_direct_mv` (lines 83–111):** `direct_scale_mv` access is explicitly bounds-checked (`(unsigned)(p_mx + tab_bias) < tab_size`). `motion_val` buffer has `+4` padding before the pointer. `block_index` values stay within allocated b8 blocks.

- **`ff_mpeg4_set_direct_mv` (lines 119–185):** `ref_index` is allocated `4 * mb_array_size` bytes; the access `4 * mb_index + 2 * i` reaches at most `4 * mb_array_size - 2` — within bounds. `mb_type` has `2 * mb_stride + 1` prefix padding.

No exploitable memory-safety vulnerabilities found.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
