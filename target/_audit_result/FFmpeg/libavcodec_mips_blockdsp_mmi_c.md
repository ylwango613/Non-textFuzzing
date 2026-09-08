Having thoroughly analyzed the file and its full calling context:

- `ff_fill_block16_mmi` / `ff_fill_block8_mmi`: All callers (`bink.c`, `jvdec.c`, `mv30.c`) pass hardcoded `h` values (8 or 16). The assembly is a do-while loop, but since h is always ≥ 8 in practice, no underflow occurs. `line_size` and `block` come from internally-allocated `AVFrame` buffers, not directly from container fields.
- `ff_clear_block_mmi`: Writes exactly 8 × 16 = 128 bytes (matches `sizeof(int16_t) * 64`). Fixed offsets, no user-controlled size.
- `ff_clear_blocks_mmi`: Writes exactly 48 × 16 = 768 bytes (matches `sizeof(int16_t) * 6 * 64`). Fixed offsets at 0x00–0x2f0+16, correct boundary.

No attacker-controlled value (chunk size, field from container, nb_entries, etc.) flows into any size or pointer arithmetic in these functions. All writes are to pre-allocated frame/codec internal buffers using assembly with compile-time-constant offsets.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
