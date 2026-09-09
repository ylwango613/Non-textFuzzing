Now I have the complete picture. Let me summarize my analysis:

**Key findings from the full read:**

1. **`AVDRMPlaneDescriptor.pitch` is `ptrdiff_t`** (64-bit on 64-bit systems), not `int`. So line 439's multiplication `layer->planes[0].pitch * mpp_frame_get_ver_stride(mppframe)` is `ptrdiff_t * RK_U32` — `RK_U32` is promoted to `ptrdiff_t` before multiplication, so no 32-bit overflow occurs for normal video strides.

2. **`av_buffer_create` with `sizeof(*desc)` vs `sizeof(*combined_desc)`** — this is intentional design: the combined struct puts `AVDRMFrameDescriptor` first so `av_free(desc)` correctly frees both, and `RKMPPFrameContext` is only accessed via `opaque`, never through the buffer's data pointer. Not a vulnerability.

3. **`ff_decode_get_extradata`** just returns a pointer to the BSF's pre-validated extradata; no allocation from untrusted size.

4. **Width/height from MPP hardware** set directly on frame/context, but HW path uses DRM_PRIME and no software `av_image_alloc` is called from these values in this code path.

5. **MPP library** handles all actual decoding and frame buffer allocation — FFmpeg code here is a thin wrapper with only fixed-size struct allocations (`av_mallocz(sizeof(*combined_desc))`), none derived from untrusted input fields.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
