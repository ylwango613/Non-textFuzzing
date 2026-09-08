I've now read the complete file (654 lines, two batches) and traced the calling context in `vp9recon.c`. Here is my analysis summary before the final verdict:

**Batch 1 (lines 1-600) findings:**
- All `ff_vert_*`, `ff_hor_*`, `ff_dc_*` functions perform fixed-size SIMD loads/stores sized exactly to their block dimension (4/8/16/32 bytes). No variable-length or externally-controlled sizes.
- `ff_tm_*` functions access `src_top_ptr[-1]` (lines 433, 463, 512, 597) — the VP9 "top-left" pixel.

**Batch 2 (lines 594-654):** `ff_tm_32x32_lsx` — same pattern, `src_top_ptr[-1]` at line 598. No other anomalies.

**`src_top_ptr[-1]` safety analysis (vp9recon.c):**
- The caller (`intra_recon` at line 232) allocates `LOCAL_ALIGNED_32(uint8_t, a_buf, [96])` and sets `a = &a_buf[32]`, so `a[-1] = a_buf[31]` is always in-bounds.
- When `TM_VP8_PRED` is active, `check_intra_mode` explicitly writes `(*a)[-1]` (line 164: `assign_bpp(*a, -1, topleft, -1)`) before handing `a` to the prediction function — the top-left is always populated.
- `TM_VP8_PRED` is remapped away (lines 64-65) to modes that don't access topleft when `have_left=0` or `have_top=0`, so the TM functions are only ever called when both neighbors exist.
- The one case where `*a = top` (frame buffer pointer, line 123) is conditioned on `have_left && top == topleft`, meaning the frame buffer's preceding byte is also valid.

**No memory allocation, no external-controlled sizes, no reachable OOB path in this file.**

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
