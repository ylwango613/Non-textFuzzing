Now I have a full picture. Let me do the final computations:

**MAX_MB_SIZE analysis:**
- `ASV1_MAX_BLOCK_SIZE = 8 + 10*49 + 5 = 503`
- `ASV1_MAX_MB_SIZE = 6 * 503 = 3018`
- `ASV2_MAX_BLOCK_SIZE = 4 + 8 + 16*(6 + 4*13) = 940`
- `ASV2_MAX_MB_SIZE = 6 * 940 = 5640`
- `MAX_MB_SIZE = (5640+7)/8 = 705 bytes`

**Line 300 integer overflow in `encode_frame`:**
`c->mb_height * c->mb_width * MAX_MB_SIZE + 3` — all `int` operands, could overflow with large video dimensions (e.g. 32768×32768 → 2,959,872,705 > INT32_MAX). However `ff_alloc_packet` takes `int64_t` — but the overflow happens in 32-bit before promotion, wrapping to a negative value → `ff_alloc_packet` returns `AVERROR(EINVAL)` (line 64-68 of encode.c checks `size < 0`). For the rare case where the overflow wraps to a small positive value, the `av_assert0(put_bytes_left(&a->pb, 0) >= MAX_MB_SIZE)` at line 202 of `encode_mb()` would catch any underallocated buffer before any OOB write occurs. The net result is DoS (error return or abort), not heap corruption.

**Scantab bounds in `asv1_encode_block`/`asv2_encode_block`:**
For `i=0..9`, `ff_asv_scantab[4*i]` gives at most `ff_asv_scantab[36] = 0x30 = 48`. Access `block[48+9] = block[57]` < 64 ✓. For ASV2, `count>>2` ≤ 15, max `ff_asv_scantab[60] = 0x36 = 54`, `block[54+9] = block[63]` ✓.

**`handle_partial_mb` row-replication analysis:**
The for-loop breaks before executing `block += 8`, so `last_row` points to the last filled row. The second loop correctly fills rows [height_avail..7] from that row. For height_avail=8, the second loop never executes. `AV_COPY128` copies 16 bytes = exactly 8 `int16_t` values = one row. No OOB access.

**Level tables:**
`asv1_put_level` guards `if (index <= 6)` before accessing `ff_asv_level_tab[7]`; `asv2_put_level` guards `if (index <= 62)` before `ff_asv2_level_tab[63]`. Both correct.

This is an **encoder** file processing raw frames (not a parser of untrusted bitstream data). The codec parameters (`width`/`height`) come from encoder configuration. All potential integer overflow paths are mitigated by existing `ff_alloc_packet` size checks and `av_assert0` guards before any output buffer write occurs.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
