I have now read the complete `aac_parser.c` (61 lines) and traced its entire call chain:

- `aac_sync` → `ff_adts_header_parse_buf` → `ff_adts_header_parse`
- `ff_aac_ac3_parse` (in `aac_ac3_parser.c`)
- `adts_header.c`, `aac_ac3_parser.c`

**Analysis summary per function group:**

**`aac_sync` (aac_parser.c:30-44):**
- `tmp[8 + AV_INPUT_BUFFER_PADDING_SIZE]` = `tmp[72]`. `AV_WB64` writes 8 bytes to `tmp[0..7]`.
- Pointer passed to `ff_adts_header_parse_buf`: `tmp + 1`, giving exactly `7 + 64 = 71` bytes — matches the function's required `AV_AAC_ADTS_HEADER_SIZE + AV_INPUT_BUFFER_PADDING_SIZE`. No overflow.
- `ff_adts_header_parse` reads exactly 56 bits (12+1+2+1+2+4+1+3+1+1+1+1+13+11+2 = 56) — all within the 7 bytes initialized by `AV_WB64`. No OOB read.

**`ff_aac_ac3_parse` (aac_ac3_parser.c:32-172):**
- `buf[i]` access in the sync loop (line 57-60): `i` ranges from `s->remaining_size` to `buf_size-1` — in bounds.
- Line 151-153: `buf_size < AV_AAC_ADTS_HEADER_SIZE` check gates the `ff_adts_header_parse_buf` call; `buf` at that point comes from `ff_combine_frame` which guarantees padding. Safe.
- `bit_rate` uninitialized when neither AC3 nor AAC config branch executes: compile-time configuration issue only, not a runtime memory-safety bug.
- No `malloc`/`av_malloc` calls with unchecked size arithmetic in this path.
- No `memcpy` with attacker-controlled sizes without prior bounds checks.

**`ff_adts_header_parse` (adts_header.c:30-74):**
- `hdr->bit_rate` computed as `size * 8 * sample_rate / samples` — `samples` = `(rdb+1)*1024`, minimum 1024, so no division by zero. `size` is bounded between `AV_AAC_ADTS_HEADER_SIZE` and 8191 (13-bit field). No overflow.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
