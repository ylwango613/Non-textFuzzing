After reading the full file and all related source/headers, here is my analysis summary:

**Batch 1 (lines 1–247, roqvideodec.c):**
- `chunk_size` is `unsigned long`, read via `bytestream2_get_le32`. Clamped to available bytes at line 74–77 before use in the VQ loop. Safe.
- `nv1`/`nv2` are byte-derived (0–255 → at most 256 after normalization). Arrays `cb2x2[256]`/`cb4x4[256]` are indexed with values in [0, 255] — safe.
- VQ loop positions (`xpos`, `ypos`, `xp`, `yp`, `x`, `y`) are derived from a loop that wraps at `ri->width`/`ri->height` (enforced as multiples of 16 in `roq_decode_init`), keeping all subblock origins and their derived ±2/±4 offsets within frame bounds.
- `bytestream2_get_byte` returns 0 on exhaustion (confirmed in bytestream.h) — no OOB read from exhausted stream.

**Batch 2 (roqvideo.c — `ff_apply_vector_2x2`, `ff_apply_vector_4x4`, `apply_motion_generic`):**
- Vector functions write into frame at `(y*stride + x)` and up to `(y+3)*stride + (x+3)` for 4×4. No explicit bounds check, but callers always pass coordinates bounded by the loop structure above.
- `apply_motion_generic`: source MV bounds `(mx, my)` explicitly checked against `[0, width-sz] × [0, height-sz]` before `block_copy`. Destination `(x, y)` is bounded by the outer loop.
- `block_copy` is a plain `memcpy` loop using the caller-supplied `sz`; no additional overflow path.

**bytestream2 API (bytestream.h):**
- `bytestream2_tell` returns `int`; `bytestream2_get_bytes_left` returns `int`. Arithmetic in the loop condition (`chunk_start` + `chunk_size`) is well-typed and doesn't overflow on 64-bit targets after clamping.

No allocations with attacker-controlled sizes exist in this file. All memory access patterns are bounded and safe.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
