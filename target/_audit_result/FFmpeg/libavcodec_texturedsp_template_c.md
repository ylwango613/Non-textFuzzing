After reading the full template and all callers (hapdec.c, hapenc.c, dds.c, dxv.c, vbndec.c, vbnenc.c) I checked every dimension path systematically:

**Template logic analysis:**
- `h_block / ctx->slice_count` — potential div-by-zero if slice_count=0. Every caller uses `av_clip(thread_count, 1, coded_height/TEXTURE_BLOCK_H)`. Since av_image_check_size2 explicitly rejects `h==0`, coded_height≥4, giving denominator≥1.
- `(off + x) * ctx->tex_ratio` — potential int32 overflow requiring `(w/4)*(h/4)*tex_ratio > INT_MAX`. av_image_check_size2 enforces `8*w*(h+128) < INT_MAX`, bounding the max product to ~INT_MAX/8 ≈ 268M, far below INT_MAX.
- Frame-buffer pointer arithmetic `y * ctx->stride * TEXTURE_BLOCK_H` — stride is ptrdiff_t (64-bit on LP64), no overflow.
- VBN negative-stride path — correctly initialises `stride = -linesize` and `frame_data.out = last_row`, so the block-write loop walks upward inside the frame without going OOB.
- DXV `tex_data.in = ctx->tex_data + tex_ratio/2` — accesses the second 8-byte channel of each 16-byte BC5 block; last accessed byte is `tex_data + tex_size - 1`, in bounds.
- DXV ctexdsp_ctx slice_count — guarded by `if (coded_height/2/TEXTURE_BLOCK_H < 1) return AVERROR_INVALIDDATA` (line 949).

All size-validation multiplications in callers stay within int32 thanks to av_image_check_size2's stride constraint. No exploitable memory-safety path was found.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
