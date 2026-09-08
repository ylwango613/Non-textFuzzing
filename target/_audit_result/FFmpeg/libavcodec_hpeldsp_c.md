Based on my thorough analysis of `hpeldsp.c` (371 lines, fully read) plus its included templates (`hpel_template.c`, `pel_template.c`) and the calling context from `mpegvideo.c`, `snowenc.c`, and architecture-specific init files, here is my assessment:

**Analysis summary:**

1. **No memory allocation** — `hpeldsp.c` contains zero `av_malloc`/`av_realloc`/`memcpy` calls. All pixel operations work on pre-allocated frame buffers supplied by callers.

2. **Frame buffer padding** — The `pixels[2]` access in `_pixels2_xy2_8_c` (line 144, 150) for a 2-pixel-wide block, and the `AV_RN32(pixels + 1)` reads reading 1 byte beyond the block width in `_pixels4/8_xy2_8_c` are standard FFmpeg half-pel interpolation patterns. They rely on frame buffers being allocated with `AV_INPUT_BUFFER_PADDING_SIZE` (64 bytes) of padding — guaranteed by `av_frame_get_buffer()` used by all callers. Not exploitable.

3. **`put_no_rnd_pixels_tab[3][4]` partial init** — Only indices [0] and [1] are initialized (lines 349–350). Index [2] is left zero-initialized. The header comment (hpeldsp.h:80) explicitly documents this: "The size is kept at [3][4] to avoid out of bounds accesses in the motion estimation code." This is intentional padding, not a bug.

4. **No external input parsing** — These are pure DSP functions. The `block`, `pixels`, `line_size`, and `h` parameters come from internal codec state (MPEGEncContext, etc.), not directly from untrusted container fields. No attacker-controlled size calculations reach this file.

5. **No integer overflow** — Stride-based pointer arithmetic (`i * src_stride1`) uses `ptrdiff_t` types and never involves attacker-supplied values that bypass bounds checks.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
