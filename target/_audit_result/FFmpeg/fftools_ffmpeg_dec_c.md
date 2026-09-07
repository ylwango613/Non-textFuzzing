Having now read all 1795 lines of `ffmpeg_dec.c` across multiple batches, and traced the relevant upstream dimension-validation functions (`av_image_check_size2`) and every subtitle decoder's own bounds checks, I have verified the following:

**Finding 1 — `copy_av_subtitle` int multiplication (line 505):** `src_rect->h * src_rect->linesize[j]` (both `int`) could theoretically wrap, but `av_image_check_size2` enforces `(w+padding)*(h+128) < INT_MAX` before any dimensions reach the subtitle rect, guaranteeing `h * w < 2^31`. DVB decoder validates via `av_image_check_size2` directly; PGS bounds subtitle dims against video dims which are themselves validated; DVD dims derive from 10-bit MPEG fields (max ≈ 1023). The overflow path is structurally blocked.

**Finding 2 — `get_buffer` VIEW_ID dereference (line 1386):** `*(int*)sd->data` without a size check is a code-style issue, but `AV_FRAME_DATA_VIEW_ID` is always created with `sizeof(int)` bytes by every caller in the codebase (e.g., `refs.c` HEVC decoder, H.264 decoder), so it cannot be triggered by a crafted stream.

**Remaining patterns** (`outputs_mask` truncation, subtitle_header_size + 1, multiview bitmask logic): all either fail-safe to ENOMEM or cause only logical (non-memory-safety) bugs.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
