After reading all ~3400+ lines of this file in 6 complete passes, I have completed the analysis.

**Summary of findings across all function groups:**

- **Chunk 1 (lines 1–600)**: Static helper functions (`avc_luma_hv_qrt_*`), `ff_put_h264_qpel*_mc00`, `ff_put_h264_qpel*_mc10/30/20` — pure SIMD register computation, no allocation.
- **Chunk 2 (lines 601–1200)**: `ff_put_h264_qpel16_mc10/30`, `ff_put_h264_qpel8/4_mc10/20/30` — same pattern; fixed-size frame-buffer reads with pre-established stride.
- **Chunk 3 (lines 1200–1800)**: `ff_put_h264_qpel*_mc01/03`, `ff_put_h264_qpel*_mc11/13/31/33`, `ff_put_h264_qpel*_mc21/23` — two-pass (horizontal + vertical) filters; all `src -= 2 * stride` halo accesses are standard H.264 padding requirements expected by the caller.
- **Chunk 4 (lines 1800–2400)**: `ff_put_h264_qpel8_mc21/23`, `ff_put_h264_qpel4_mc21/23`, `ff_put_h264_qpel*_mc02`, `ff_put_h264_qpel*_mc12/32` — same SIMD pattern.
- **Chunk 5 (lines 2400–3100)**: `ff_put_h264_qpel*_mc22`, `ff_avg_h264_qpel*_mc00/10/30` — averaging-mode variants; no new patterns.
- **Chunk 6 (lines 3100–end)**: `ff_avg_h264_qpel8_mc10/30` and remaining avg functions — identical structure.

**Why no vulnerabilities**: This file is a pure SIMD DSP computation layer. It:
- Performs no dynamic memory allocation (no `av_malloc`, `malloc`, `realloc`, `memcpy` with attacker-controlled sizes).
- Parses no bitstream data — `src`/`dst` buffers and `stride` are passed in from the H.264 decoder core which has already validated dimensions and allocated padded frame buffers.
- Uses SIMD vector loads/stores on pre-allocated frame buffers whose size is determined by the decoder, not by this file.
- All `src - 2` / `src - 2*stride` halo accesses are contract requirements documented by the H.264 standard and fulfilled by the caller's pre-padded frame buffer.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
