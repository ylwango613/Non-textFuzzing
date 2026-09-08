I have now read all 1331 lines of `h264pred_template.c` in three batches, cross-checked the header `h264pred.h`, `bit_depth_template.c`, the call sites in `h264_mb.c`, `h264_mb_template.c`, and the buffer declarations in `h264dec.h`.

Key findings from the analysis:

- **No dynamic allocation**: every prediction function receives pre-allocated codec buffers; no `malloc`/`av_malloc` is called.
- **Block accesses are fixed-size**: all writes are bounded to 4×4, 8×8, or 16×16 pixel regions within internally-allocated frame planes.
- **`block_offset` is in bounds**: `h->block_offset[96]` and all call paths (including `pred8x16_vertical_add` which reaches index max 43 from base 0) stay within those 96 elements.
- **`mb[]` buffer is sufficient**: `int16_t mb[16*48*2]` = 3072 bytes; the maximum access in `pred8x16_vertical_add` reaches ≈2548 bytes from the base, well within bounds.
- **`topright` NULL handling is correct**: only `DIAG_DOWN_LEFT_PRED` / `VERT_LEFT_PRED` functions dereference `topright`, and the call site in `h264_mb.c:677-693` always sets it to a valid pointer (stack-synthesised or real frame data) before dispatching those modes; all other modes receive NULL but never dereference it.
- **Arithmetic values**: sums of pixel values (max 65535 each, ≤32 terms) and H/V gradient computations stay well within 32-bit `int` range.
- **Type-punning `int16_t *` → `dctcoef *`**: a known FFmpeg pattern using DECLARE_ALIGNED; accesses remain within the allocated `mb` region.

No attacker-controllable size field is fed into any memory operation in this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
