Having fully read `eaidct.c` (90 lines), its header, and all three caller files (`eatgq.c`, `eamad.c`, `eatqi.c`), I performed the following checks:

- **block[] bounds**: `ea_idct_col` accesses `block[i+0, i+8, ..., i+56]` for i=0..7. Maximum index = 63; all callers supply a 64-element `int16_t[64]` block. ✓
- **temp[] bounds**: Written by ea_idct_col at `temp[i+0..i+56]` (max 63), read by IDCT_ROW at `temp[8*i..8*i+7]` (max 63). ✓
- **dest[] writes**: IDCT_ROW writes to `dest[j]` for j=0..7 per row (i=0..7), with row stride `linesize`. The `linesize` comes from `ff_get_buffer`, not from the media file, and is bounded by the allocated frame size. ✓
- **block[0] += 4**: Arithmetic on int16_t; values are bounded by quantization tables and are nowhere near INT16_MAX in practice. Not UB-exploitable for memory corruption. ✓
- **IDCT arithmetic**: All intermediate values use `int` (32-bit) arithmetic with bounded int16_t inputs; no overflow that would cause memory corruption. ✓
- **MUNGE_8BIT**: `av_clip_uint8((x)>>4)` always produces a valid byte — no OOB write to `dest`. ✓
- **Callers validate block decode indices**: Both `tgq_decode_block` (line 85-86) and `decode_block_intra` in eamad.c (lines 149, 163) return `AVERROR_INVALIDDATA` if the zigzag scan index ≥ 64, preventing OOB writes into the block. ✓

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
