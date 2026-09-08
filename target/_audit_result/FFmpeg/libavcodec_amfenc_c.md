**Analysis summary:**

`amfenc.c` is an **encoder** wrapper around AMD's AMF GPU SDK. Key observations after full read (727 lines, two passes):

1. **`swprintf` → `av_memdup` (lines 90–96):** If `swprintf` returns −1, `alloc_size = 0` and `av_memdup(name, 0)` returns NULL, which is caught by the null-checks at lines 92–93/97–98. Not exploitable.

2. **`amf_copy_buffer` line 206 `memcpy`:** `size` comes from `buffer->pVtbl->GetSize()` on an AMF GPU-driver object, and `pkt->data` was allocated by `ff_get_encode_buffer` with the same `size`. Both sizes are from the trusted GPU driver, not from a parsed media file.

3. **Pointer-as-int64_t (lines 374/386):** On 64-bit platforms (where AMF runs), `sizeof(AVFrame*) = sizeof(int64_t) = 8`, so the pointer round-trips through `int64_t` correctly. On 32-bit, upper bytes are uninitialized but retrieval also only copies `sizeof(frame_ref) = 4` bytes, so the correct low-4-byte pointer is recovered. No memory safety issue.

4. **`amf_copy_surface` / `av_image_copy2` (lines 186–188):** Uses `avctx->width`/`avctx->height` from the encoder context, not from untrusted bytes parsed here.

5. **No media file parsing at all:** This file is an encoder. It does not read container bytes, atom sizes, chunk lengths, extradata, or seek tables. All data flows originate from already-decoded `AVFrame` objects or from the GPU driver. There is no direct attack surface from a crafted media file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
