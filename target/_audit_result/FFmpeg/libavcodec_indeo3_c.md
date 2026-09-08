I've now read the complete file across two passes and checked all related structures and macros. Let me summarize the analysis of all key functions before reaching a final verdict:

**`allocate_frame_buffers` (lines 169-228):** Dimensions strictly bounded [16,640] × [16,480]. Max luma_size = 640 × 481 = 307,840 — no integer overflow possible.

**`decode_frame_headers` (lines 901-1019):** `y_offset/v_offset/u_offset` validated before pointer arithmetic. `ctx->data_size` clamped to `buf_size - 16`. `ctx->alt_quant = gb.buffer` in worst case points to end of packet; reads `ctx->alt_quant[0..15]` are at most within the 64-byte `AV_INPUT_BUFFER_PADDING_SIZE` padding — no crash, and subsequent `prim_indx/second_indx >= 24` validation catches any garbage values.

**`decode_plane` (lines 860-896):** The unsafe `bytestream_get_le32` at line 869 reads within packet bounds because `y_offset < ctx->data_size - 16`. `num_vectors` capped at 256. `init_get_bits` return value unchecked but overflow requires packet > ~268 MB.

**`decode_cell` (lines 586-725):** The initial `code = *data_ptr++` at line 598 lacks a `ctx->next_cell_data < ctx->last_byte` pre-check, but `bytes_used` from a prior `decode_cell` call is bounded by `last_ptr - data_start` (via BUFFER_PRECHECK), so `ctx->next_cell_data ≤ ctx->last_byte`. Worst case: a 1-byte read from the 64-byte padding (returns 0, triggers error path). VQ indices validated against 24-entry `vq_tab`. Requantize loop `ref_block[x]` (x < cell->width×4): motion-vector bounds checks at lines 621-627 ensure writes stay within the allocated plane buffer.

**`decode_cell_data` (lines 432-570):** Every data read guarded by `BUFFER_PRECHECK`. All `dst` writes bounded by `CHECK_CELL` (verified before each `decode_cell` call at line 842). RLE counter `rle_blocks` ≤ 30 (from `(code & 0x1F) - 1` with `code < 64`). `num_lines` checked `> 0` before use.

**`copy_cell` (lines 238-288):** Full motion-vector bounds check at lines 253-259 before any pointer arithmetic.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
