**Analysis complete across all four batches (lines 1–1094).**

**Batch 1 findings (1–300):**
- `av_fast_padded_malloc/z`: proper `SIZE_MAX - AV_INPUT_BUFFER_PADDING_SIZE` guard before addition — safe.
- `ff_set_dimensions`: delegates to `av_image_check_size2` — safe.
- `avcodec_align_dimensions2`: has explicit `if (desc)` guard after `av_pix_fmt_desc_get` (line 149) — safe.
- `avcodec_align_dimensions` (line 370): `desc->log2_chroma_w` accessed without null check — real null-deref bug, BUT grepping confirms this function is never called anywhere else in FFmpeg's own `.c` files; it is a deprecated public API only, not in the `ffmpeg -i` decode hot path.

**Batch 2 findings (300–600):**
- `avcodec_fill_audio_frame`: proper `av_samples_get_buffer_size` + `buf_size < needed_size` guard — safe.
- `get_audio_frame_duration`: `ch < 32768 && bps < 32768` guard before multiplying; `ATRAC3` overflow check `framecount > INT_MAX/1024` present — safe.
- Line 745 `tmp = blocks * ((ba - 4 * ch) / (bps * ch) * 8)` is int×int without LL suffix (UB risk), but `tmp` is only returned as frame duration, not passed to any allocator — not a memory-safety bug.

**Batch 3 findings (600–900):**
- `av_xiphlacing`, `avpriv_find_start_code`, `ff_thread_ref_frame`, `ff_thread_replace_frame` — all bounded cleanly.

**Batch 4 findings (900–1094):**
- `ff_alloc_timecode_sei`: maximum bits written = 2 + 3×41 = 125 bits < allocated 128 bits — no write overflow. `tc[0]` read without size check is a read-safety concern, but side data size is set by FFmpeg internals at allocation; not externally triggerable from a raw media file.
- `ff_alloc_timecode_metadata_av1`: 40 bits written into 40-bit (5-byte) buffer — exact fit, no overflow.
- `ff_guess_coded_bitrate`: calls `av_get_bits_per_pixel(desc)` where desc could be NULL if pix_fmt invalid (line 1088) — null deref, but only called from encoder initialization (rawenc.c, v210enc.c, etc.), not from the media-file demux/decode path.

**Callee cross-checks confirmed:** `av_get_bits_per_pixel` dereferences its argument unconditionally (pixdesc.c:3415). `avcodec_align_dimensions` is not called by any other FFmpeg `.c` file. `av_get_audio_frame_duration2` results feed only into packet duration metadata, not into any allocation size.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
