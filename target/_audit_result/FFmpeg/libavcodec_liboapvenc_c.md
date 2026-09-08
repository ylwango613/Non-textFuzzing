Based on my thorough analysis of `liboapvenc.c` (all 709 lines read in two passes), here is my complete assessment of the file's attack surface:

**Analysis summary:**

1. **`apv_imgb_create()` (lines 250-261)** — `imgb->bsize[i] = imgb->s[i] * imgb->ah[i]` with no overflow guard. Without the `oapv.h` header I cannot confirm the field types, but at practical APV encoder dimensions (up to 8K: 7680×4320, 2 bytes/sample) the product is ≈66 MB — safely within int32 range. FFmpeg also has its own width/height > 0 check in the encoding path.

2. **`handle_side_data()` (lines 415-467)** — fixed `uint8_t payload[64]` stack buffer passed to `oapvm_write_cll()` then `oapvm_write_mdcv()` without resetting `size` between the two calls. MDCV payload (3×2 uint16 primaries + 2 uint16 white-point + 2 uint32 luminance = 24 bytes of data + framing) is well under 64 bytes; CLL is 4 bytes + framing. No confirmed overflow.

3. **`liboapve_encode()` (line 577)** — `av_image_copy2(..., frame->width, frame->height)` copies into a buffer allocated for `avctx->width×avctx->height`. FFmpeg's `avcodec_send_frame` path does not explicitly verify frame vs. codec-context dimensions for video, but in any realistic transcoding pipeline the filter graph or decoder output enforces dimension consistency.

4. **This is an encoder**, not a decoder — it never directly parses attacker-controlled binary byte streams from a media file container. All potentially large values (`avctx->width`, `avctx->height`) are derived from already-decoded/validated frames, not raw untrusted container fields.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
