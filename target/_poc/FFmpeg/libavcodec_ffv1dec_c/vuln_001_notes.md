# VULN-001: FFV1 Heap OOB Read/Write via Crafted Quant-Table Context Index

## PoC Strategy
Craft an AVI file with FFV1 v3 video where:
1. Extradata encodes quant tables with context_count=1 (all tables have ret=1)
2. Frame data with non-zero pixels to produce non-zero diffs → context ≥ 1 → OOB

## Trigger Path
```
ffmpeg -i crafted.avi -f null -
→ avformat_open_input → avcodec_open2 → decode_init → ff_ffv1_read_extra_header
→ decode_frame → decode_slices → decode_slice
→ ff_ffv1_init_slice_state (allocate p->state = context_count * 32 bytes)
→ decode_plane → decode_line → get_context → p->state[context]
```

## Vulnerability Analysis — WHY OOB IS UNREACHABLE (False Positive)

### The invariant in read_quant_table / ff_ffv1_read_quant_tables

In `ffv1_parse.c`:
- `read_quant_table` returns `ret = 2 * v_final - 1` where `v_final` is the count of distinct quant values
- `ff_ffv1_read_quant_tables` passes `context_count` (before multiplication) as the scale to each table
- Scale for table i = product of all previous ret values

The mathematical invariant:

For table i with v_final_i distinct values, using scale_i:
- Max contribution to context = scale_i * (v_final_i - 1)
- context_count multiplier = ret_i = 2 * v_final_i - 1

Since `v_final_i - 1 < 2 * v_final_i - 1` for all v_final_i ≥ 1, each table's contribution
is strictly less than its multiplier's factor.

Summing over all 5 tables (with cumulative scale = cumulative product of previous ret values):

max_context = Σ scale_i * (v_final_i - 1)
            < Σ scale_i * (2*v_final_i - 1) / 2
            = (product of all ret_i) / 2
            ≤ p->context_count   [from the (context_count+1)/2 formula]

This can be proven by induction and is an invariant of the quant table encoding.

### Specific cases

All-zero tables (ret=1 per table, context_count=1):
- quant_table values: all 0 (scale * v = 1 * 0 = 0)
- get_context() always returns 0
- context=0 < context_count=1 ✓ (no OOB)

Tables with two levels (ret=3 per table, context_count=122):
- Max context = 1+3+9+27+81 = 121 < 122 ✓ (no OOB)

### Memory management verification

For v3 (version > 2), the slice init sequence is:
1. `ff_ffv1_init_slice_state(f, sc)` — allocates p->state using p->context_count (=0, so zero-size alloc)
2. `decode_slice_header(f, sc, p)` — reads quant_table_index, sets p->context_count; if increased, FREES p->state
3. `ff_ffv1_init_slice_state(f, sc)` again — if p->state is NULL, allocates correctly

This double-init pattern ensures the state is always correctly sized for the actual context_count.

### Conclusion

The `av_assert2(context < p->context_count)` at ffv1dec_template.c:77 is a no-op in release
builds, but it would NEVER fire even if enabled, because the quant table encoding system
mathematically guarantees context < context_count for any valid (or attackers-crafted-but-parsed)
quant table configuration.

**The reported vulnerability is a false positive.**

## Files Generated
- `vuln_001_input.avi` (256 bytes): context_count=1, all-zero quant tables
- `vuln_001_input2.avi` (267 bytes): context_count=2, half-split first quant table
- Both decode cleanly with no ASAN errors (exit 0, no ASAN reports)

## Status: UNVERIFIED
The crafted files are parsed without error and no memory safety violation is triggered.
The reported OOB is unreachable due to the mathematical invariant in the quant table system.
