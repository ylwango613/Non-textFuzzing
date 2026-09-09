Now I have the full picture. Let me complete the analysis:

**`bytestream2_get_byte` (checked)**: at line 74 — if buffer exhausted, clamps to buffer_end and returns 0. Safe.

**`bytestream2_get_bufferu` (unchecked)**: at line 281 — raw `memcpy` with no bounds check. This is the 'u' (unsafe) variant.

Now verifying the one usage of `bytestream2_get_bufferu` in `qpeg.c` (line 109):
- Before the loop, `copy` is clamped to `bytestream2_get_bytes_left()` (line 105-106)
- Each iteration uses `step = FFMIN(copy, ...)` ≤ `copy`
- `copy -= step` is decremented by the same amount as the buffer advances
- Invariant `copy ≤ bytes_left` is maintained throughout — so the unchecked read never overflows input buffer

Now verifying the output buffer (dst) bounds in both decode functions:
- `filled` is always reset to 0 when it reaches `width`; writes are always to `dst[filled]` where `filled ∈ [0, width-1]`
- `dst` is decremented by `stride` per row; `rows_to_go`/`height` counters prevent going past the top of the frame
- Motion compensation in `qpeg_decode_inter` (lines 183-185): six-term guard covers all four edges of both source and destination blocks — negative `me_x`/`me_y` are handled correctly

No allocation calls in this file — all buffers are frame-allocated by `ff_get_buffer`. No integer overflow paths leading to undersized allocations. `decode_flush` computes `pal_src` safely via `FFMIN(1024U, extradata_size)`. The `ref->data[0] == NULL` case is explicitly handled in `qpeg_decode_inter` line 144-146.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
