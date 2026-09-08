Having thoroughly examined:
- `msgsmdec.c` (the primary file, 39 lines)
- `gsmdec_template.c` (included into msgsmdec.c, containing all decode logic)
- `gsmdec_data.c` / `gsmdec_data.h` (all lookup tables)
- `gsm.h`, `msgsmdec.h` (constants and declarations)
- `gsmdec.c` (caller/driver code including `gsm_init` validation)
- `gsm_parser.c` (parser layer)

Key findings from my analysis:

**`ref_buf[280]` bounds**: Starting at index 120, the 4-iteration loop writes up to index `240 + offset(0-3) + 36 = max 279`, which is exactly the last valid index. No overflow.

**Table indexing**: All lookups are bounded — `maxidx` from 6 bits → 0–63 (table has 64 rows); `gain_idx` from 2 bits → 0–3 (table has 4 entries); `frame_bits[i]` values are only 1, 2, or 3 (from static `apcm_bits` arrays), keeping `ff_gsm_requant_tab[frame_bits[i]]` within bounds [0..3]; `val` width ≤ 3 bits → 0–7, matching the 8-element second dimension.

**`mode` parameter**: Validated in `gsm_init` to produce values 0–8, matching the 9-row `ff_gsm_apcm_bits` array.

**`init_get_bits` with `GSM_MS_BLOCK_SIZE * 8` vs. smaller `block_align`**: Potentially reads into padding region, but this is protected by FFmpeg's `AV_INPUT_BUFFER_PADDING_SIZE` guarantee (≥64 bytes), and the decoder's bit consumption matches the block_align for each mode.

**Sample buffer**: `ff_get_buffer` allocates `2 * GSM_FRAME_SIZE = 320` samples; both `gsm_decode_block` calls stay within their 160-sample windows.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
