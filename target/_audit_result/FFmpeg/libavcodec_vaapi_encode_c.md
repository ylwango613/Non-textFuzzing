Having fully read all 2382 lines of `vaapi_encode.c` and verified the key helper definitions:

**Key findings from analysis:**

1. **`vaapi_encode_make_misc_param_buffer` stack buffer (line 128):** The `av_assert0(buffer_size <= sizeof(buffer))` is confirmed (avassert.h:42) to be **always-active** — it cannot be compiled away (unlike C's `assert()`). It will `abort()` rather than silently overflow. Pure DoS at worst, no exploitable memory corruption.

2. **TOCTOU in `vaapi_encode_get_coded_data` (lines 735–757):** The buffer size is measured in one `vaMapBuffer`/`vaUnmapBuffer` cycle, then read again in a second cycle. A malicious VAAPI driver returning larger sizes in the second pass would overflow the allocated packet buffer. However, the VAAPI driver is trusted kernel/driver code at the same or higher privilege level — this is not an attacker-controlled trust boundary for FFmpeg's security model.

3. **Integer overflow `3 * surface_width * surface_height` (line 2083):** On 32-bit `int`, resolutions ≥ ~27K×27K would overflow signed int, but (a) such resolutions are rejected by codec-specific caps before reaching this point, and (b) this creates a VAAPI driver buffer of wrong size, not a direct OOB write in FFmpeg's own heap.

4. **ROI side-data loop (lines 553–569):** `roi_size = roi->self_size` could be smaller than `sizeof(AVRegionOfInterest)`, causing adjacent-memory reads in the stride iteration. However, `AV_FRAME_DATA_REGIONS_OF_INTEREST` is added by filters/applications, **not** synthesized by any FFmpeg decoder from the bitstream — the attacker cannot inject it via a crafted media file.

5. **This file is an encoder, not a decoder/demuxer.** The primary attack surface (`ffmpeg -i <malicious_file>`) does not directly reach encoder code unless the input is first decoded by a different codec component. The encoder itself processes application-supplied frames and user-specified options.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
