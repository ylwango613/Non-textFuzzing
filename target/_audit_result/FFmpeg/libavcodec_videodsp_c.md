I have now fully read:
- `videodsp.c` (64 lines — pure initialization, no data processing)
- `videodsp_template.c` (102 lines — the `emulated_edge_mc` implementation)
- `videodsp.h` (function signatures)
- `bit_depth_template.c` (`pixel` typedef: `uint8_t` or `uint16_t`)

**Analysis summary:**

`videodsp.c` is a thin initialization file that installs function pointers; no untrusted data is processed here. The actual logic is in `videodsp_template.c`'s `emulated_edge_mc`, which performs edge padding for motion compensation:

- **Line 36 assertion** (`block_w * sizeof(pixel) <= FFABS(buf_linesize)`) is `av_assert2` — stripped in release builds. However, the parameters (`block_w`, `buf_linesize`) come from FFmpeg's internal decoder layer, not directly from the container bitstream. The buf is allocated by `av_frame_get_buffer` with padding that enforces this invariant before reaching here.
- **Pointer arithmetic** at lines 39, 40, 44, 49, 52 uses `ptrdiff_t` arithmetic; `src_y`/`src_x` are clamped before use via the `if` branches at lines 38–53.
- **Row copies** (`memcpy` at lines 69, 75, 83) use `w * sizeof(pixel)` where `w = end_x - start_x`, clamped by `FFMIN(block_w, ...)` — no overflow path reachable from container fields.
- **Left/right fill loops** (lines 92–98) index `bufp[x]` for `x` in `[0, block_w)`, within the allocation guaranteed by callers.
- **No `av_malloc`/`av_realloc` calls**, no extradata handling, no seek-table parsing, no chunk-size arithmetic in this file.

All parameters flow from FFmpeg's internal motion-compensation layer, not directly from attacker-controlled container bytes, and frame dimensions are validated upstream before any call into this DSP layer.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
