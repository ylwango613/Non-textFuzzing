After thoroughly reading `hap.c` (78 lines), `hapdec.c` (439 lines), `hap.h`, and cross-referencing the related bytestream/memory utilities, here is a complete analysis of all code paths:

**Section 1 — `ff_hap_parse_section_header` (hap.c:58-78)**
- 3-byte section_size read via `bytestream2_get_le24` → max 0xFFFFFF (16M), fits in int.
- When section_size == 0, 4-byte value read via `bytestream2_get_le32` (uint32_t → int). Values ≥ 0x80000000 become negative; caught by `*section_size < 0` guard.
- Final check `*section_size > bytestream2_get_bytes_left(gbc)` (both int) prevents section_size from exceeding available bytes. No bypass possible.

**Section 2 — `ff_hap_set_chunk_count` (hap.c:29-49)**
- Calls `av_reallocp_array` with int `count` promoted to `size_t nmemb`. For negative or huge count, `av_reallocp_array` internally detects overflow and returns error, which is propagated correctly.
- Double-realloc pattern: if second realloc (`chunk_results`) fails, `chunks` remains valid but `chunk_count = 0`, preventing further use.

**Section 3 — `hap_parse_decode_instructions` (hapdec.c:47-116)**
- HAP_ST_COMPRESSOR_TABLE: `section_size` → `ff_hap_set_chunk_count(ctx, section_size, ...)`. Loop reads exactly `section_size` bytes, within bounds validated by the header parser.
- HAP_ST_SIZE_TABLE: `section_size / 4` chunks allocated. Since section_size ≥ 0, division is safe. Loop reads section_size/4 × 4 bytes ≤ section_size bytes.
- HAP_ST_OFFSET_TABLE: Same pattern, uint32_t offsets stored in `compressed_offset` (uint32_t). Safe.
- Offset-reconstruction loop checks `compressed_size > UINT32_MAX - running_size`, preventing uint32_t overflow in the running sum.

**Section 4 — `hap_parse_frame_header` / `hap_decode` (hapdec.c:131-337)**
- `chunk->uncompressed_offset = ctx->tex_size` assigns `size_t` → `int`. However, `tex_size` is validated immediately after against `(coded_width / TEXTURE_BLOCK_W) * (coded_height / TEXTURE_BLOCK_H) * tex_ratio`, which for maximum supported dimensions (≤16384×16384) and tex_ratio≤16 is ≤268M, well within int range. Truncation impossible under valid input.
- `chunk->compressed_offset + (uint64_t)chunk->compressed_size > bytestream2_get_bytes_left(gbc)` — cast to uint64_t prevents overflow in this bounds check, correctly guards OOB.
- `av_reallocp(&ctx->tex_buf, ctx->tex_size)` allocates exactly the validated tex_size. The `decompress_chunks_thread` writes only within allocated bounds using `uncompressed_offset` (bounded as above).
- `ff_snappy_peek_uncompressed_length` returns int64_t; negative values are error-checked before storage in `size_t chunk->uncompressed_size`.

**Section 5 — Multi-texture path (hapdec.c:263-294)**
- `start_texture_section += ctx->texture_section_size + 4`: potential int overflow only with packets > 2GB, which are unreachable in practice and not a memory-safety exploit.

All allocation sizes are bounded by validated section_size (≤ packet bytes remaining), all array accesses are guarded by chunk_count, and all memcpy/decompress destinations are within allocated buffers.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
