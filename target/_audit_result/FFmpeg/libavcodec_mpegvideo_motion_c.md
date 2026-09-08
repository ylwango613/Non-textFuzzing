I've now read the complete 846-line file and investigated all relevant context:

**Batch 1 (lines 1–600):** Analyzed `hpel_motion`, `mpeg_motion_internal`, `mpeg_motion`, `mpeg_motion_field`, `put_obmc`, `obmc_motion`, `qpel_motion`, `chroma_4mv_motion`, `prefetch_motion`, and the start of `apply_obmc`. All motion coordinates are clipped before pointer arithmetic; emulated-edge fallback is taken whenever a source coordinate is out-of-range.

**Batch 2 (lines 600–846):** Analyzed `apply_8x8` and `mpv_motion_internal`/`ff_mpv_motion`. Function-pointer array indices: `dxy` is always 0–3 for hpel and 0–15 for qpel; `chroma_x_shift` is always 0 or 1; all within statically sized tables.

**`apply_obmc` motion_val bounds:** The bottom-row accesses (`mot_xy + mot_stride`, `mot_xy + mot_stride + 1`) — at the worst-case last MB row they evaluate to `b8_array_size − 3` and `b8_array_size − 2` respectively, both within the allocated pool (`2 * (b8_array_size + 4)` elements). Top/left/right edges all have explicit guards. No OOB.

**`edge_emu_buffer` size:** Allocated as `alloc_size * 280` bytes (i.e., 280 rows of `linesize` bytes). The deepest user is the Y+U+V layout (`18*linesize + 20*uvlinesize`), which for 4:4:4 totals ≤ 38 rows of `linesize` — well under 280. No overflow.

**No direct file-input parsing:** This file operates entirely on motion vectors already stored in `s->mv[dir][i]` and `cur_frame->motion_val`, populated upstream by codec-specific parsers. There are no `av_malloc`, `memcpy`, or extradata size fields processed here.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
