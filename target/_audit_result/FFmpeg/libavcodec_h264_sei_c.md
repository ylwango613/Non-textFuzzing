After fully reading `h264_sei.c` (347 lines) in one pass, plus examining all related code in `h2645_sei.c`, `h2645_sei.h`, `h264_sei.h`, and `h264_ps.c`, here is a summary of what each critical path looks like:

**Batch 1 (lines 1–302) — h264_sei.c core**
- `decode_picture_timing`: copies into `uint8_t payload[40]`; guarded by `if (size > sizeof(h->payload))` check first. Safe.
- `decode_buffering_period`: loops `sched_sel_idx < sps->cpb_cnt` writing to `initial_cpb_removal_delay[32]`; `cpb_cnt` is validated to `<= 32` in `h264_ps.c`. Safe.
- `ff_h264_sei_decode` type/size accumulation: `size` is `unsigned` and always checked against `bytestream2_get_bytes_left` before use; `type` (signed int) could overflow with billions of 0xFF bytes but is impractical to trigger and all dispatched handlers have their own bounds checking.

**h2645_sei.c — shared handlers**
- `decode_film_grain_characteristics`: `num_intensity_intervals[c] = get_bits(gb,8)+1` max 256; arrays are `[3][256]`. Inner loop index max 255 — exactly in bounds. `num_model_values` validated `<= 6`; array third dim is 6. Safe.
- `decode_unregistered_user_data`: `size >= INT_MAX-1` guard before `av_buffer_alloc(size+1)`. Safe.
- All other handlers (`mastering_display`, `content_light`, `ambient_viewing_environment`, `alternative_transfer`) validate remaining bytes before reading fixed-size fields.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
