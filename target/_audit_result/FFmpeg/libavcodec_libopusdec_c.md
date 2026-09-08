The file is 251 lines. I've read it fully and traced all key paths:

- **Lines 56-106** (`libopus_decode_init`): `channels` from `extradata[9]` (uint8_t), clamped. Extradata bounds check at line 81 (`extradata_size >= OPUS_HEAD_SIZE + 2 + channels`) guards the mapping read. The channel remapping loop at 103–104 uses `vorbis_offset[ch]` values from a static table; for all `channels` 3–8, max offset = `channels - 1`, which is within the guaranteed bounds. No overflow.

- **Lines 160–204** (`libopus_decode`): `ff_get_buffer` allocates `channels * MAX_FRAME_SIZE * sample_size`. `opus_multistream_decode` is given `frame->nb_samples = MAX_FRAME_SIZE = 5760` as the max, so the library respects this ceiling. Gain loop multiplication: max `255 * 5760 = 1,468,800` — fits in `int`.

- **`nb_streams`/`nb_coupled`** from extradata at lines 82–83: both uint8_t, passed to libopus which validates them before creating the decoder.

No memory safety vulnerabilities found in this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
