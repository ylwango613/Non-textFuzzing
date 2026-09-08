After exhaustive multi-batch analysis of the full file (h264_mb.c, h264_mb_template.c, h264_mc_template.c) and all related headers/callers, including:

- All array-index calculations using `ref_cache` (int8_t), `scan8[]`, `refs[2][48]`, `ref_list[2][48]`, `implicit_weight[48][48][2]`, `luma_weight[48][2][2]`, `chroma_weight[48][2][2][2]`
- The bipred_scratchpad layout and `(8 << pixel_shift + (chroma_idc == 3))` operator-precedence expression at line 409
- Boundary conditions in `await_references` / `get_lowest_part_y` for possibly-negative ref_n
- mc_part's `implicit_weight[ref_cache[0][...]][ref_cache[1][...]]` dereference when list0 && list1
- motion-vector offset arithmetic in `mc_dir_part` and the emulated-edge protection
- top_borders pointer arithmetic in `xchg_mb_border`

Key findings and why each is **not** an externally-triggerable memory-safety bug:

1. **`(8 << pixel_shift + (chroma_idc == 3))` operator-precedence** (line 409): computes `8 << (pixel_shift + (chroma_idc == 3))` rather than likely-intended `(8 << pixel_shift) + (chroma_idc == 3)`. This causes `tmp_cb` and `tmp_cr` to be at incorrect offsets inside the bipred_scratchpad, producing wrong chroma values in bidir-predicted B-frames. However, all accesses remain **within** the `16 * 6 * alloc_size`-byte allocation — no heap overflow.

2. **Negative `ref_n` in `get_lowest_part_y` / `mc_part`**: `ref_cache` is `int8_t`, and `LIST_NOT_USED = -1` / `PART_NOT_AVAILABLE = -2`. A negative ref_n used as an index into `refs[2][48]` or `ref_list[2][48]` would be OOB. However, both CABAC (h264_cabac.c:2147) and CAVLC (h264_cavlc.c:877) parsers **validate** ref_idx against ref_count and return error on overflow. When IS_DIR(mb_type/sub_mb_type, list) is true, the parsed ref is always >= 0. When IS_DIR is false, list0/list1 flags are also false, preventing entry to the array-index path.

3. **`implicit_weight` pre-condition in `mc_part`** (h264_mc_template.c:51): evaluated only when `use_weight == 2 && list0 && list1`. Both conditions being true guarantees both ref_cache values are in [0, 47], as established above.

4. **`top_borders[top_idx][mb_x - 1]` when mb_x == 0**: the pointer is computed unconditionally (UB) but is never dereferenced — guarded by `if (deblock_top) { if (deblock_topleft)` where `deblock_topleft = (sl->mb_x > 0)`.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
