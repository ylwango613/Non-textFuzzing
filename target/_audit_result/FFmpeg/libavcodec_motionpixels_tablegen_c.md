Now I have the complete picture for analysis.

**Summary of findings:**

1. **`motionpixels_tablegen.c`** is a build-time table generator (`main()` that generates a `.h` file). It is compiled separately and never executed at runtime by the decoder — no external input is processed.

2. **`motionpixels.c`** (the actual runtime decoder, all supporting context):
   - `changes_map` alloc: `av_calloc(width, h4)` where `h4 = (height+3)&~3 ≥ height`. All accesses bounded by h4 via the `continue` guard in `mp_read_changes_map` and the h4 padding for the +1/+2/+3 row reads in `mp_decode_line`.
   - `hpt` accesses: formula `((y/4)*W + x)/4` — proven strictly less than `(h4/4)*(w4/4)` for all valid y < H, x < W.
   - `vpt` accesses: y < height always; alloc is `height * sizeof(*mp->vpt)`. Safe.
   - `codes_count` from 4 bits → 0..15; `codes[]` has 16 elements (MAX_HUFF_CODES). Safe.
   - `mp_yuv_to_rgb` with `clip_rgb=1`: YuvPixel values are clamped (y: 0..31, v/u: ±31); resulting `r*8`, `g*8`, `b*8` indices are -168..416, -128..376, -216..464 respectively, all within `ff_crop_tab[256 + 2*384]` (1024 bytes). Safe.
   - `av_calloc` for all allocations handles internal overflow checks.
   - All bitstream-derived offsets are validated (`y >= height → continue`) before use as array indices.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
