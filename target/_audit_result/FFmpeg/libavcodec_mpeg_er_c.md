After thorough analysis of all 120 lines of `mpeg_er.c` plus the full call chain through `error_resilience.c`, `mpegvideo.c`, and `mpegvideo_dec.c`:

- **`set_erpic`**: only copies pointers, no allocation, no OOB risk.
- **`ff_mpeg_er_frame_start`**: thin wrapper, no allocation.
- **`mpeg_er_decode_mb`**: `memcpy(s->mv, mv, sizeof(*mv))` copies `sizeof(int[2][4][2])` = 64 bytes to a 64-byte destination — exact match; `dest[]` pointer arithmetic uses `mb_y`/`mb_x` bounded by the loop in `ff_er_frame_end` (`0 ≤ mb_y < mb_height`, `0 ≤ mb_x < mb_width`); `ff_mpv_reconstruct_mb(s, NULL)` — callee explicitly guards `if (!block) return`.
- **`ff_mpeg_er_init`**: `dc_val[1]` / `dc_val[2]` pointer arithmetic mirrors exactly the layout computed in `ff_mpv_init_context_frame` (`y_size = b8_stride*(2*mb_height+1)`, etc.), so no OOB pointer is produced; `int*int*int` intermediate could theoretically overflow but only at dimensions (~370 k pixels wide) that no supported MPEG variant allows.
- **`ff_er_init`** (callee): `unsigned mb_array_size = mb_height * mb_stride` uses `unsigned` but same dimension constraints apply; `av_malloc_array` for `er_temp_buffer` is safe.

No externally triggerable memory safety bug was found in this file or its immediate call chain.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
