I've now fully analyzed `bethsoftvid_decode_frame` and all the called functions. Let me summarize the critical code paths examined:

**Frame write bounds** (`dst` / `frame_end`): `dst` starts row-aligned and advances exactly `linesize[0]` per row in the inner loop. The equality check `dst == frame_end` is mathematically sufficient — it cannot overshoot — because each step is exactly `remaining + wrap_to_next_line = linesize[0]`, and `frame_end = data[0] + linesize[0] * height`.

**Input reads**: `bytestream2_get_buffer` clips to `FFMIN(available, size)`, never reading past the packet end. Output destination (`dst`) write size is bounded by `remaining ≤ avctx->width ≤ linesize[0]`, within the allocated frame row.

**`memset` calls**: Both `memset(dst, ..., remaining)` and `memset(dst, ..., length)` are bounded by the row invariant `dst + remaining = end_of_current_row ≤ frame_end`.

**`set_palette`**: Reads exactly `256*3` bytes (guarded at line 60), writes exactly 256 `uint32_t`s to `data[1]` (the PAL8 palette allocation is always 1024 bytes).

**`yoffset`**: Validated `< avctx->height` before applying the row offset.

**Block type**: Only values 1–4 accepted (line 84), all handled in switch/case.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
