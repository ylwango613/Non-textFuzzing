All table sizes verified:
- `ff_mjpeg_bits_dc_luminance[17]` → `+1` with 16 bytes reads [1..16] ✓
- `ff_mjpeg_bits_ac_luminance[17]` → `+1` with 16 bytes reads [1..16] ✓  
- `ff_mjpeg_bits_ac_chrominance[17]` → `+1` with 16 bytes reads [1..16] ✓
- `ff_mjpeg_val_dc[12]` → 12 bytes read ✓
- `ff_mjpeg_val_ac_luminance[162]` → 162 bytes read ✓
- `ff_mjpeg_val_ac_chrominance[162]` → 162 bytes read ✓

`append_dht_segment` writes exactly 5+16+29+12+1+16+162+1+16+162 = 420 bytes, matching `dht_segment_size = 420`.

`output_size = in->size - input_skip + sizeof(jpeg_header) + dht_segment_size` = `(in->size - input_skip) + 20 + 420`, which exactly equals the bytes written. The bounds check `if (in->size < input_skip)` prevents reading beyond the input buffer. The `input_skip` field-value (from attacker-controlled `in->data[4..5]`) can be at most 65535 + 4 = 65539, well within `int` range. No allocator size mismatch exists.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
