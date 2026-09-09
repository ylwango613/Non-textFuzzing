Completed full analysis. Summary of findings:

**Key candidates examined:**

1. **`edge_emu_buffer + 16` for V chroma** in `ff_vc1_mc_4mv_chroma4` and `ff_vc1_mc_4mv_chroma`: when `uvlinesize == 16`, the V emulation buffer (at `+16`) aliases with U's second row (also at offset `16 = 1 * uvlinesize`). This causes V's emulated rows to overwrite U's emulated rows. This is a **data correctness bug** (wrong decoded pixels), but all accesses remain within the generously allocated `alloc_size * 280`-row `edge_emu_buffer`. No OOB write occurs.

2. **Field_mode luma emulation height (2k-1 = 37 rows)** writing past `ubuf = edge_emu_buffer + 19 * linesize` in `ff_vc1_mc_1mv`: luma emulation extends into the ubuf region, but chroma emulation re-populates that region afterward before any chroma reads occur. Total max extent ~37 × linesize, well within 280 × linesize buffer.

3. **`vc1_scale_luma/chroma` with interlace emulation**: odd stride rows exist in interlace path but `vc1_scale_luma` (k rows) matches what was actually written by the two interleaved `emulated_edge_mc` calls together. No OOB.

4. **Array bounds for `mv`, `luty`, `luma_mv`, `mv_f`**: all indices are 0/1 (flag values & 1, `ref_field_type[dir]` which is 0 or 1), and `mv[dir][0..3][0..1]` fits in the `[2][4][2]` declaration. `luma_mv[mb_x]` is bounded by `mb_stride`. No OOB.

5. **No `av_malloc` / `av_realloc` calls in this file**: vc1_mc.c is a pure motion-compensation module — it performs no allocations and reads no size fields from the bitstream. All buffers it writes into are pre-allocated by the calling infrastructure.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
