After thorough analysis of all 272 lines of `mpeg12.c` plus the relevant callers (`mpeg12dec.c`, `eatqi.c`) and headers (`mpeg12dec.h`, `rl.h`):

- `ff_mpeg1_decode_block_intra()`: All three call sites pass `index` strictly in [0..5], making `component = index <= 3 ? 0 : index - 4 + 1` always in {0,1,2} — safe for `last_dc[3]`.
- The `i > MAX_INDEX` check (MAX_INDEX=63) guards every access to `scantable[i]` and `block[j]`.
- Escape-code `run = SHOW_UBITS(re,gb,6)+1` (max 64) followed by the same `> MAX_INDEX` break ensures `i` never exceeds 63 before `j = scantable[i]`.
- `quant_matrix[j]` — j is a scantable value (compile-time constants 0..63), quant_matrix is a 64-element table.
- `UNCHECKED_BITSTREAM_READER` is intentional FFmpeg design, mitigated by AV_INPUT_BUFFER_PADDING_SIZE at the allocation site.
- VLC table initialization (`ff_init_2d_vlc_rl`) operates entirely on static compile-time arrays.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
