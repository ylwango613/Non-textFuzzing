I've now read the complete file (690 lines) in two batches and examined the relevant macros and call context. Here is my analysis of all function groups:

**Batch 1 (lines 1–600):**
- `intra_predict_vert_8x8/16x16_msa`: reads exactly 8 or 16 bytes from the row above, writes 8×8 or 16×16 pixels. Fixed SIMD block sizes, no user-controlled lengths.
- `intra_predict_plane_8x8_msa` line 150: `LD_UB(src - (stride + 1))` reads 16 bytes for an 8×8 top row. This loads 7 bytes beyond the block's top row — standard SIMD over-read pattern; FFmpeg guarantees ≥16-pixel horizontal padding in frame buffers, so no OOB in practice.
- `intra_predict_plane_16x16_msa` lines 219–220: two 8-byte `LD` calls covering exactly the 16-pixel top row plus top-left corner. Correct.
- All DC/horizontal/vertical prediction functions: fixed-size reads (`LD_UB` = 16 bytes) from `src - stride`, writes 8×8 or 16×16 blocks with `SD4`/`ST_UB8`. No dynamic sizes.

**Batch 2 (lines 600–690):**
- Remaining wrapper functions (`ff_h264_intra_pred_dc_left_16x16_msa`, `ff_h264_intra_pred_dc_top_16x16_msa`, `ff_h264_intra_pred_dc_128_*`, `ff_vp8_pred*`): all delegate to static helpers with fixed 8×8 or 16×16 block logic. No allocation, no user-controlled sizes.

**Key observations:**
- No `malloc`/`av_malloc`/`memcpy` calls anywhere in this file — no integer-overflow-to-underalloc or heap overflow paths.
- No bitstream parsing — stride and src pointers come from the H.264 decoder after frame buffer allocation.
- All array indices are compile-time constants or bounded uint8_t arithmetic (max range ~±255×4×17 = well within int32_t).
- `ptrdiff_t stride` → `int32_t` narrowing in internal helpers is safe for any valid video frame (max stride ≪ INT32_MAX).
- Frame buffers in FFmpeg's H.264 decoder carry at least 16-pixel horizontal and vertical padding before intra prediction is invoked, covering all SIMD over-reads.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
