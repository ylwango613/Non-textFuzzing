Based on my complete read-through of all 2702 lines plus the included `aacdec_latm.h`, and following up with `grep` checks on all key structures and constants, here is a summary of what I verified for each category:

**Group 1 (lines 1–500):** `count_channels`, `che_configure`, `frame_configure_elements`, channel-layout helpers — all array accesses bounded by `MAX_CHANNELS=64`, `MAX_ELEM_ID=64`; no integer overflow in index arithmetic.

**Group 2 (lines 500–1000):** `ff_aac_output_configure`, `decode_pce` (including height extension) — `layout_map[MAX_ELEM_ID*4][3]` (256 rows); max PCE tags = 63 (sum of 4-bit + 2-bit + 4-bit fields). `height_map[4][16]` used at indices 1–3; `tag[6][16][3]` used at indices 1–5. All within bounds. Conservative overread guard at line 852 (counts CC twice, but safe in the safe direction).

**Group 3 (lines 1000–1500):** `decode_ga_specific_config`, `decode_eld_specific_config`, `decode_audio_specific_config*`, `decode_ics_info` — `group_len[8]` accessed at max index 7; `max_sfb` validated against `num_swb` before use; `max_sfb * num_window_groups` ≤ 8×15=120 < 128 (band_type/sfo size).

**Group 4 (lines 1500–2000):** `decode_band_types`, `decode_scalefactors`, `decode_pulses`, `ff_aac_decode_tns`, `decode_mid_side_stereo`, `decode_dynamic_range` — `band_top[17]`/`dyn_rng_*[17]` with max `drc_num_bands`=16; `exclude_mask[64]` with max writes of 63 entries; all within declared array sizes.

**Group 5 (lines 2000–2702 + LATM):** `decode_extension_payload`, `spectral_to_sample`, `parse_adts_frame_header`, `aac_decode_frame*`, `latm_decode_audio_specific_config`, `read_payload_length_info` — LATM `esize` bounded by `FFMIN(asclen, get_bits_left(gb))`; no allocation underflow; `mux_slot_length` overflow-to-negative is caught by `< 0` guard.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
