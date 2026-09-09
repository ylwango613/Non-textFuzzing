I now have all the information needed. Let me consolidate the full analysis:

**`bytestream2_get_levarint` (lines 32-47):** The `shift > 31` guard and the `((tmp & 127LL) << shift) > INT_MAX` check together cap the maximum decoded varint at exactly INT_MAX (2,147,483,647). The arithmetic is done in `long long` to avoid UB. So `decode_len` can only return values in [0, INT_MAX].

**`snappy_literal` (lines 49-76):** `size` receives `len` (int64_t) cast to `int`. Since `len ≤ INT_MAX` (proven above), no truncation ever occurs. The `size < len` signed-vs-unsigned comparison is safe because `size` is always non-negative. The unsigned-int overflow case (val=63, LE32=0xFFFFFFFF → `len=0`) writes 0 bytes, harmless.

**`snappy_copy` (lines 78-92):** Back-reference bounds check `off > p - start` is correct on x86-64 (unsigned int promoted to ptrdiff_t). `size < len` is correct with both as `int`.

**`decompress_chunks_thread` (hapdec.c:236):** Passes `ctx->tex_size` (total) instead of `ctx->tex_size - chunk->uncompressed_offset` as the size limit. This is a latent logical error, but NOT exploitable: both `ff_snappy_peek_uncompressed_length` in `hap_parse_frame_header` and `decode_len` inside `ff_snappy_uncompress` read the same varint bytes from the same compressed buffer, so `len` always equals `chunk->uncompressed_size`, and `chunk->uncompressed_offset + chunk->uncompressed_size ≤ ctx->tex_size`.

**Dimension bound:** The `tex_size != expected` check (hapdec.c:287-292) fires before `decompress_chunks_thread` is launched, and `av_image_check_size` caps `coded_width × coded_height` such that `tex_size ≤ 256 MB ≪ INT_MAX`, precluding any int-truncation path.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
