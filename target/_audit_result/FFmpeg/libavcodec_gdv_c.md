**Batch 1 analysis (lines 1–576, full file):**

Key observations across all functions:

**`gdv_decode_init` (line 62):** `avctx->width * avctx->height + PREAMBLE_SIZE` — potential integer overflow, but `avcodec.c:241-245` calls `av_image_check_size2()` and resets dimensions to 0 before `init` is called. Mitigated by framework.

**`bytestream2_put_byte` / `bytestream2_get_byte` (DEF macro, lines 59-79):** Both are bounds-checked. `put_byte` only writes if `!p->eof && buffer_end - buffer >= 1`; `get_byte` returns 0 past end. No OOB possible via these.

**`bytestream2_seek` SEEK_SET (line 226-229):** Clamps offset to `[0, buffer_end - buffer_start]`. The `lz_copy` function's negative-start case (`start = tell_p - |off|`) is safe because `tell_p >= PREAMBLE_SIZE = 4096` and max `|off| = 4096`, giving `start >= 0`.

**`bytestream2_skip_p` (line 180-190):** Clamps to buffer end via FFMIN. The `flags >> 8` skip value (up to 16M) is safe.

**`decompress_2/5/68`:** All writes go through bounds-checked `bytestream2_put_byte`; all LZ back-references use bounded `bytestream2_seek`/`get_byte`. Maximum `len` values (up to ~65K in tag==0 b==1 path) still go through the clamped API.

**`rescale` / `scaleup` / `scaledown`:** All pointer arithmetic stays within `PREAMBLE_SIZE + width*height` — verified by walking worst-case y/x indices for each branch.

**`gdv_decode_frame` memcpy (line 529):** `sidx` ranges from `PREAMBLE_SIZE` to `PREAMBLE_SIZE + height*width - 1`; last byte accessed is `frame[frame_size-1]`. Within bounds.

**Direct array accesses (`decompress_68` lines 405-406):** `gdv->frame[bytestream2_tell_p(pb) - real_off]` where `real_off` ≤ 8 and `tell_p >= skip + PREAMBLE_SIZE >= PREAMBLE_SIZE = 4096`. Minimum index = 4096-8 = 4088 ≥ 0, and `tell_p` is always within `frame_size`.

All potentially dangerous patterns are either guarded by the bytestream2 bounds-checking API or by the framework-level `av_image_check_size2` validation.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
