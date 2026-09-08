After thorough analysis of `libaomdec.c` (303 lines) and all related code in the call chain:

**Group 1 (lines 1-65): `aom_init`** — Straightforward libaom init wrapper. No user-controlled allocation or buffer operations.

**Group 2 (lines 68-144): `set_pix_fmt`** — `color_ranges[img->range]` at line 73: `img->range` is `aom_color_range_t`, constrained to 0 or 1 by the AV1 spec (1-bit field); libaom decodes it via `aom_rb_read_bit()` — no OOB risk.

**Group 3 (lines 146-187): `decode_metadata` / `decode_metadata_itu_t_t35`** — `metadata->payload` and `metadata->sz` come from libaom-parsed AV1 metadata OBUs. The `buffer_size < 6` guard plus `bytestream2` in `ff_itut_t35_parse_buffer` keeps all reads bounds-checked. `ff_itut_t35_parse_payload_to_struct` uses `av_buffer_alloc`/`av_dynamic_hdr_plus_alloc` with no attacker-controlled sizes fed directly.

**Group 4 (lines 189-275): `aom_decode`** — `av_image_copy` at line 264: `picture` is allocated by `ff_get_buffer` using `avctx->width/height` already set to `img->d_w/d_h`; the `d_w ≤ w` / `d_h ≤ h` guard at line 210 ensures libaom planes are large enough. `ff_aom_image_copy_16_to_8` at line 259: the loop `i < desc->nb_components` is at most 3 (formats set in `set_pix_fmt` are all ≤ 3-plane); libaom-provided stride and plane pointers are managed by libaom and are internally consistent.

**`itut35.c` memcpy (line 279):** `av_buffer_alloc(itut_t35->payload_size)` followed by `memcpy(..., itut_t35->payload_size)` — allocation and copy use the same size; no underallocation.

No externally-triggerable memory-safety vulnerability found in this file or its immediate call chain within FFmpeg.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
