`start_count` is captured at the top of `read_restart_header` (line 533), and `get_bits_count` is monotonically non-decreasing as bits are read throughout the function — the subtraction on line 633 is always non-negative and represents many bits read from the bitstream (sync word, channel info, etc.).

**Summary of analysis:**

- `mlp.c` is 142 lines: static lookup tables + CRC/checksum utility functions — no allocation, no packet parsing, no direct handling of container-field sizes.
- `ff_mlp_checksum16`: caller (`mlp_parse.c:99`) passes `header_size - 2`; `mlp_get_major_sync_size` always returns -1 (caught) or ≥ 28, so `buf_size` ≥ 26 — safe.
- `ff_mlp_checksum8`: caller (`mlpdec.c:1372`) uses `substream_data_len - 2`; the preceding check at line 1368 ensures `substream_data_len * 8 - get_bits_count == 16`, guaranteeing `substream_data_len ≥ 2` before the call. The do-while loop always reads ≥ 1 bit first, so `buf_size == 0` is not reachable.
- `ff_mlp_restart_checksum`: `bit_size = get_bits_count(gbp) - start_count` where `start_count` is captured at entry and many bits are read before line 633 — always a large positive value.
- `ff_mlp_calculate_parity`: loop structure is safe for any `buf_size` including 0.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
