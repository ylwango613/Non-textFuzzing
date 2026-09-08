**Batch 1 (lines 1–328, full file reviewed):**

- `weight_h264_pixels##W` / `biweight_h264_pixels##W`: All pixel writes are to `block[0..W-1]` / `dst[0..W-1]` where W ∈ {2,4,8,16} is a compile-time constant. No dynamic allocation, no unchecked index. `log2_denom` shifts affect only arithmetic values (not pointer offsets), and results are always clipped by `av_clip_pixel()` before storing.
- `h264_loop_filter_luma` / `h264_loop_filter_luma_intra`: Pixel reads/writes span `pix[-4*xstride]` to `pix[3*xstride]`; these are within pre-allocated frame buffer margins, bounded by the frame's stride×height allocation. `tc0` is always accessed at indices 0..3 — confirmed from h264_loopfilter.c that callers always allocate `int8_t tc[4]` on the stack filled from a static 4-column lookup table.
- `h264_loop_filter_chroma` / `h264_loop_filter_chroma_intra`: Same pattern — fixed `inner_iters` × ystride stride steps, `tc0` always 4 elements, no allocation arithmetic.
- No `av_malloc`/`memcpy`/`realloc` in this file. No attacker-controlled size feeds a heap allocation. No container field reaches any of these functions as an array index or allocation size.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
