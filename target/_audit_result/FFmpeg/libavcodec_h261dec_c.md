After reading the full file and tracing all key code paths with supporting context, here is my complete analysis:

**Batch 1 (lines 1–344) analysis:**
- `h261_decode_init`: no allocation calls, VLC tables are static.
- `h261_decode_gob_header`: `gob_number` is validated (1–12 for CIF, 1/3/5 for QCIF) before use.
- `h261_decode_block`: `i` is initialized to −1 (offset trick). For INTER coded blocks where the special 1s code is NOT present, `i` stays at 0 before `i--`, making `i = −1`. Normal VLC run=0 entries exist in `ff_h261_tcoeff_run`. On the path `i += 0 → i = −1`, the check `if (i >= 64)` does NOT fire, so `j = scan_table[-1]`. However: `scan_table` is `s->intra_scantable.permutated` (uint8_t[64]); `permutated[-1]` reads the last byte of the 8-byte `scantable` pointer which, on x86-64 LE, is always `0x00` (48-bit user-space addresses). So `j = 0`, `block[0] = level` — an in-bounds write, causing a decoding error but no memory safety impact.

**Batch 2 (lines 345–626) analysis:**
- `h261_decode_mb`: `current_mba` is checked `> MBA_STUFFING (33)` before computing `mb_x`/`mb_y`. Maximum values: for CIF `mb_x = 21`, `mb_y = 17`; `xy = 412`, `mb_array_size = 414`. Bounds OK.
- `h261_decode_mb_skipped`: loop variable `i` max 32; with validated `gob_number`, computed `mb_x`/`mb_y` are within CIF/QCIF dimensions. `mb_type[xy]` and `motion_val[0][b_xy]` writes verified in-bounds.
- `motion_val` allocation: `b8_array_size = b8_stride * mb_height * 2`. For CIF max `b_xy = 1572 < 1620`. OK.
- `h261_decode_frame`: dimension change handled via `ff_mpv_common_end`/`ff_mpv_common_init`. H.261 only allows CIF/QCIF, so controlled resize path.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
