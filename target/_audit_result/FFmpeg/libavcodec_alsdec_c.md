After complete multi-batch analysis of all 2228 lines of `alsdec.c` plus the MLZ, BGMC dependencies and related headers:

**Batch 1 (lines 1-500)**: `read_specific_config` — `sconf->max_order` is 10-bit (0–1023), channel positions are validated before use, `ht_size` overflow-checked against INT32_MAX before `skip_bits_long`.

**Batch 2 (lines 500-1000)**: `parse_bs_info` — recursion produces at most 32 leaf nodes, exactly fitting `div_blocks[32]`. `read_var_block_data` — `opt_order` hard-clamped to `sconf->max_order`; table lookups (`parcor_scaled_values[0..127]`, `ltp_gain_values[0..3][0..3]`) use validated indices.

**Batch 3 (lines 1000-1500)**: `decode_var_block_data` — negative-index accesses into carryover region are within the pre-allocated `raw_buffer` (offset `max_order` elements before channel start). `read_channel_data` — loop bound `entries < channels` prevents writing past the `channels`-entry row. `revert_channel_correlation` — `reverted[]` flag prevents cycles; bounds checks on `master` pointer against `raw_buffer` extents present and correct.

**Batch 4 (lines 1500-2228)**: `read_diff_float_data` — `nchars` for Part A is at most `frame_length × 4 = larray_size`; Part B at most `frame_length × 3 < larray_size`. `ff_mlz_decompression` passes `size - output_chars` as `bufsize` to each `decode_string` call, and `decode_string` checks `offset >= bufsize` before any write. `decode_init` — `channel_size = frame_length + max_order` ≤ 66559; `channels × channel_size ≤ 512 × 66559 = 34M`, within 32-bit unsigned range; `INTERLEAVE_OUTPUT` shift is always ≥ 0; `crc_buffer` matched to `bswap_buf` output size for 32-bit sample format.

No exploitable memory-safety vulnerabilities confirmed.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
