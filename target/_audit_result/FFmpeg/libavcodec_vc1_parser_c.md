Now I have complete context. Let me do a final summary of the analysis:

**Batch 1 analysis (lines 1-282) — complete file:**

Key structures:
- `unesc_buffer[UNESCAPED_LIMIT]` = 144 bytes; only filled up to `UNESCAPED_THRESHOLD` = 37 bytes
- `unesc_index` is `size_t` — compared against UNESCAPED_THRESHOLD (37) in every write loop

**Potential concern 1 — EOF `memset` underflow:**
Line 147: `memset(unesc_buffer + unesc_index, 0, UNESCAPED_THRESHOLD - unesc_index)` — `size_t` subtraction could wrap if `unesc_index > 37`. The inner while loop condition is `unesc_index < UNESCAPED_THRESHOLD`, so after any write `unesc_index ≤ 37`. No wraparound possible.

**Potential concern 2 — `bytes_to_skip` signed/unsigned arithmetic:**
`vpc->bytes_to_skip` is `size_t`; adding negative `int next` relies on unsigned wrap. With `bytes_to_skip=4` and `next ∈ {-3,-2,-1}`, unsigned wrap gives 1, 2, 3 — all correct and < INT_MAX, so `int i = vpc->bytes_to_skip` is safe.

**Potential concern 3 — `GetBitContext` read past initialized bytes:**
`vc1_extract_header` calls `init_get_bits8(&gb, buf, unesc_index)` with at most 37 bytes. Then `show_bits_long(gb, 32)` reads 4 bytes. The buffer is 144 bytes (zeroed by `av_mallocz`), so reads into the uninitialized region return zeros — no OOB into unmapped memory.

**Potential concern 4 — `parse_only` flag protection:**
`vpc->v.parse_only = 1` causes `ff_vc1_parse_frame_header` (line 654) and `ff_vc1_parse_frame_header_adv` (line 989) to return before any code that accesses uninitialized `bitplane` arrays or LUT pointers. `rotate_luts` is unreachable in parser context.

**Potential concern 5 — `hrd_num_leaky_buckets` loop:**
5-bit value from bitstream, bounded at [0,31]; only calls `skip_bits` in a loop — no array indexing, no allocation.

All code paths in `vc1_parser.c` and the immediately reachable callees (`ff_vc1_decode_sequence_header`, `ff_vc1_decode_entry_point`, `ff_vc1_parse_frame_header`, `ff_vc1_parse_frame_header_adv`) operate within well-bounded buffers and are protected by the `parse_only` flag where needed. No exploitable memory safety vulnerability was found.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
