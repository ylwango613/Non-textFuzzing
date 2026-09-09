I have now fully analyzed the entire `vb.c` file (291 lines) across all functions. Here is a complete accounting of every pattern I checked:

**`decode_init` (lines 261–262):** `av_mallocz(avctx->width * avctx->height)` — the signed-int multiplication looks like a CWE-190 candidate, but `avcodec_open2` calls `ff_set_dimensions` → `av_image_check_size2` before invoking `decode_init`. That check enforces `stride*(h + 128ULL) < INT_MAX` (with `stride = 8w + 1024`), limiting allowable dimensions to ~16 000×16 000 where `w*h ≪ INT_MAX`. Any dimensions large enough to overflow `int` would cause `ff_set_dimensions` to return an error and `goto free_and_end`, aborting init before `decode_init` is ever reached. Not exploitable under normal FFmpeg usage.

**GMC offset check (line 215):** `FFABS(j) > avctx->height` is an off-by-one (should be `>=`), allowing `j = height`. This shifts `prev` exactly one frame-width beyond `c->prev_frame`, but every `prev`-read is guarded by `check_line` / `check_pixel` (which compare against `pend = c->prev_frame + width*height`). The check fails when the pointer is past `pend`, and `memset` is used instead — no heap read or write out of bounds.

**Unchecked x-offset `i` (line 213):** `i` (`int16_t`, [-32768, 32767]) is not validated against `avctx->width`. Same defense applies: `check_line`/`check_pixel` bound-check every `prev`-based read; writes always go to `cur` which tracks through the frame buffer by the block grid.

**`cur` pointer (all block cases):** Block grid iterates `(width>>2)*(height>>2)` blocks, advancing `cur` by exactly `width*height` bytes in total. For any valid (non-overflowed) dimension pair, writes stay within the `av_mallocz(width*height)` allocation. No unchecked OOB write path exists.

**`vb_decode_palette` (lines 61–77):** `start ∈ [0,255]`, `size ∈ [0,255]`. The guard `start+size > 255` ensures the loop `for (i=start; i<=start+size; i++)` accesses at most `c->pal[255]` — valid for a 256-element array. No overflow in `size*3+2` (max 767). Safe.

**Stream reads (`bytestream2_*`):** All reads use the ByteStream2 API which internally clamps reads to remaining data. No OOB read from the packet buffer.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
