After thorough analysis of `/data/ylwang/non-textfuzz/target/FFmpeg/libavcodec/vp6dsp.c` and its full call chain:

**vp6_filter_diag4_c (lines 30–61):**
- Stack buffer `tmp[8*11]` (88 ints): first loop writes exactly `tmp[0..87]` (11 rows × 8 cols), second loop reads `tmp[0..87]` — no out-of-bounds access.
- `src[x-1]` to `src[x+2]` reads: standard DSP tap, always protected by the 12×12 `emulated_edge_mc` in `vp56_mc()` before the call.
- `h_weights[0..3]` / `v_weights[0..3]`: always point into the static `vp6_block_copy_filter[17][8][4]` table; indices `select` ∈ {0..16} and `x8`/`y8` ∈ {0..6} (luma, after ×2 with mask=3) or {0..7} (chroma, mask=7) are all within bounds.
- Integer arithmetic: `uint8_t × int16_t` products (max 255×128 = 32640) summed 4× plus bias fit comfortably in `int32_t`.

**ff_vp6dsp_init (lines 63–70):** trivial function-pointer assignment, no memory operations.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
