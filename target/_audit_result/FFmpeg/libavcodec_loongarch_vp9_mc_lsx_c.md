I've completed a thorough 5-pass analysis of all 2480 lines. Let me summarize the complete findings:

**Group 1 (lines 1-500)**: Horizontal 8-tap filter functions for 4w/8w/16w/32w/64w. All SIMD loads are within VP9 reference frame bounds. `src -= 3` is covered by VP9's `VP9_INTERP_EXTEND=4` border padding.

**Group 2 (lines 500-797)**: Vertical 8-tap filter functions. Prologue reads `src - 3*stride` (3 rows above src), which is within the VP9 border. Loop counts `height >> 2` are correct for valid VP9 block heights (multiples of 4).

**Group 3 (lines 797-1177)**: Combined H+V filters and pixel copy functions. Correct for all block sizes.

**Group 4 (lines 1177-1531)**: Avg/merge variants of hz filters. Checked `common_hz_8t_and_aver_dst_32w_lsx` — `dst_tmp` vs `dst` remain synchronized.

**Group 5 (lines 1531-2480)**: Avg variants of vt/hv filters, pixel averaging functions, and the `VP9_8TAP_LOONGARCH_LSX_FUNC` macro (lines 2372-2438).

**Key analysis of filter index access** (`vp9_subpel_filters_lsx[3][15][8]`, accessed as `[type_idx][mx-1]`):
- `type_idx` is a compile-time constant (0, 1, or 2) — always valid
- `mx-1` and `my-1`: The DSP init code (`vp9dsp_init_loongarch.c` lines 43-45) registers `h`-functions at `[idxh=1][idxv=0]`, `v`-functions at `[0][1]`, and `hv`-functions at `[1][1]`. The VP9 decoder dispatches to these functions only when `mx!=0`/`my!=0`. So `mx` is always 1–15 when the h-filter is called → `mx-1` is 0–14, within the 15-element array. No OOB.

**No memory allocation, no integer overflows affecting security, no OOB writes to dst buffers** (bounded by block dimensions from valid VP9 frames).

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
