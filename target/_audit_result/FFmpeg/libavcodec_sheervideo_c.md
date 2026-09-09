**Pass 1 (lines 1–500):** decode functions for YUVA444P10 and YUV444P10. All pixel writes use `dst[x]` bounded by `x < avctx->width`. No external allocation controlled by bitstream.

**Pass 2 (lines 500–1000):** decode_ca2p/c82p/ybyr/byryi — 422-format functions with `x += 2` loops. For odd widths, `dst_y[x+1]` at x = width–1 writes to `dst_y[width]`, which is within the linesize-padded allocation (FFmpeg aligns linesizes ≥ 64 bytes). Chroma planes for YUV422P use `AV_CEIL_RSHIFT(width, 1)` = ceil(width/2) samples, so `dst_u[x/2]` for x = width–1 (odd) resolves to `dst_u[(width-1)/2]` which is within the ceil allocation. No genuine OOB.

**Pass 3 (lines 1000–1500):** decode_ybri/ybr/aybri/aybr — 444 and YUVA444 formats with `x += 1`. All within bounds.

**Pass 4 (lines 1500–2012):** decode_argb*/decode_rgb* (packed ARGB/RGB0) with `dst[4*x + 0..3]`. Frame allocated with `linesize[0] >= 4 * width`. Writes for x in [0, width-1] are at most `dst[4*width-1]` — within allocation.

**build_vlc (lines 1781–1803):** Stack array `lens[1024]` filled from compile-time static `SheerTable` data in `sheervideodata.h`. Not attacker-controlled.

**decode_frame (lines 1805–1991):**
- Size check at line 1975: `avctx->width * avctx->height` can overflow signed int for extreme dimensions (UB → may wrap to 0), making the check trivially satisfied. However, `ff_thread_get_buffer()` is called immediately after and will fail for extreme dimensions via `av_image_check_size()` internally. The `GetBitContext` cached reader (line 23: `CACHED_BITSTREAM_READER`) safely returns 0 past end-of-buffer instead of reading out-of-bounds. No memory corruption path from this overflow.
- No `av_malloc`/`memcpy` with attacker-controlled sizes in this file.
- VLC tables sourced from compile-time static data only.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
