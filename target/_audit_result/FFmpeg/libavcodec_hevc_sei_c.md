Both `bytestream2_init` (`av_assert0(buf_size >= 0)`) and `init_get_bits8` (explicitly checks `byte_size < 0`) protect against any negative payload_size fallout. Complete analysis summary:

**Function-by-function findings:**

- `decode_nal_sei_decoded_picture_hash`: reads exactly `sizeof(s->md5[cIdx])` = 16 bytes (compile-time constant) into `uint8_t md5[3][16]`, loop bound fixed at 3. **Clean.**

- `decode_nal_sei_pic_timing`: bit reads only, no allocations. **Clean.**

- `decode_nal_sei_recovery_point`: range-checked se_golomb. **Clean.**

- `decode_nal_sei_active_parameter_sets`: explicit `[0,15]` and `[0, HEVC_MAX_SPS_COUNT)` checks. **Clean.**

- `decode_nal_sei_timecode`: `get_bits(gb, 2)` → 0–3; all arrays are `[3]`, loop up to i<3 → accesses [0..2]. **Clean.**

- `decode_nal_sei_3d_reference_displays_info`: `num_ref_displays` checked `> 31` → max 31; `s->num_ref_displays = num_ref_displays + 1` → max 32; arrays declared `[32]`; loop `i < s->num_ref_displays` accesses at most indices 0..31 → all within bounds. `get_bits64` max `length` = 62+31-31=62 < 64. **Clean.**

- `decode_nal_sei_message` payload_size loop: potential signed-integer overflow (missing `payload_size > INT_MAX - 255` guard that payload_type has), but any resulting negative `payload_size` immediately hits `av_assert0(buf_size >= 0)` inside `bytestream2_init` → program abort (DoS via assertion, not controllable memory corruption). **Not a memory-safety bug.**

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
