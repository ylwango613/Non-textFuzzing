Based on my thorough analysis of the file and all related callers, here is my conclusion:

**Group 1 — `gmc1_c` (lines 24-45)**

The function accesses up to `src[stride + 8]` on each row, running for `h` rows. The luma callers pass `h=16` with a 17×17 emulated edge buffer, and chroma callers pass `h=8` with a 9×9 buffer. The last access (`src[16*stride + 8]` for luma, `src[8*uvlinesize + 8]` for chroma) is within bounds. Arithmetic: A+B+C+D = 256 always (bilinear weights sum), so `(A*src+…)/256 ≤ 255` — no integer overflow writing `dst`.

**Group 2 — `ff_gmc_c` (lines 47-108)**

The `width--; height--;` pattern at lines 54-55 converts edge-position values (from `h_edge_pos = mb_width * 16 ≥ 16`) to last-valid-index values. All four branches are correctly bounded: the in-bounds path accesses `src[index + stride + 1]` with `src_x ≤ width-2`, `src_y ≤ height-2`, which stays within the allocated frame plane. Mixed-bounds paths use `av_clip`. The corner path reads a single pixel. Intermediate arithmetic stays well within 32-bit range for MPEG4 frame sizes. The sprite warp overflow checks at lines 638-676 guard `sprite_offset`/`sprite_delta` values before they reach this function.

**Group 3 — `gmc_ssse3` (x86 SSE3 path)**

The edge emulation buffer `(MAX_H+1) * EDGE_EMU_STRIDE = 17 * 16 = 272` bytes is correctly sized. The assembly reads rows 0 through h (h+1 total rows) with offsets 0 and 1, last byte at `h * 16 + 1 ≤ 257 < 272`. The operator precedence in `ox & (1 << (16 + shift)) - 1` correctly computes `ox & ((1 << (16+shift)) - 1)` because the inner `(1 << (16+shift))` is fully parenthesized and `-` binds tighter than `&`.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
