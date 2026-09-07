Based on my complete analysis of `/data/ylwang/non-textfuzz/target/FFmpeg/libavcodec/4xm.c`:

**Batch 1 (lines 0–600):** Reviewed `idct()`, `mcdc()`, `decode_p_block()`, `decode_p_frame()`, `decode_i_block()`, `idct_put()`. Motion vector bounds are properly checked via `start`/`end` pointer range validation. Recursive `decode_p_block` with negative `log2h`/`log2w` would hit `av_assert0` (always-on, calls `abort()`) — DoS only, not memory corruption.

**Batch 2 (lines 600–1049):** Reviewed `read_huffman_tables()`, `decode_i2_frame()`, `decode_i_frame()`, `decode_frame()`, `decode_init()`. Key findings:
- `av_mallocz(width * height * 2)` guarded by `av_image_check_size()` which bounds `stride*(h+128) < INT_MAX`, preventing overflow.
- `4 * AV_RL32(...)` in `decode_i_frame` (line 790) can wrap, but the subsequent equality check `prestream_size + bitstream_size + 12 != length` and `prestream_size > (1<<26)` correctly gate invalid states.
- The `cfrm` assembly path has a proper overflow guard at line 897.
- 1-byte OOB read potential in `read_huffman_tables` (missing check before `end = *ptr++` after `start != 0` branch) reads into the guaranteed `AV_INPUT_BUFFER_PADDING_SIZE` packet padding — not exploitable.
- `decode_i2_frame` dst writes stay within frame buffer: max access is `(height-1)*width + 15 <= height*width - 1`.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
