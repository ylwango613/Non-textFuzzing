Completed my analysis of all code paths. Let me summarize what I reviewed:

**`mss2dsp.c` (157 lines):**
- `mss2_blit_wmv9_template`: loop variables `i`, `j`, `k` all stay within declared buffer widths (j = floor(i/2), k = 3*i), and callers validate rectangle bounds.
- `upsample_plane_c`: vertical pass works backward (no dst/src aliasing), horizontal pass also backward; `plane_stride >= w` after round-up holds because VC1 frame is allocated for full `avctx->width × avctx->height`.

**`mss2.c` calling code:**
- Rectangle validation at lines 584-586 ensures `x+w ≤ avctx->width`, `y+h ≤ avctx->height` before any blit call.
- `WMV9codedFrameSize` advance without upper-bound check (lines 776-777): when `WMV9codedFrameSize > buf_size - 3`, `buf_size` goes negative, but subsequent `buf_size < 4` check (line 771) uses C `||` short-circuit — `AV_RL24(buf)` is never reached with an out-of-bounds pointer.
- `av_malloc_array` in `ff_mss12_decode_init` has internal overflow protection; `av_mallocz(pal_stride * height)` uses `ptrdiff_t` on 64-bit (no practical overflow).
- `decode_rle` / `decode_555`: bounds validated before pointer arithmetic; VLC symbol range is 0–255, staying within `pal[256]`.
- `upsample_plane` called with `(w+1)>>1` for chroma (correct C precedence: `+` > `>>`); rounded-up width stays within `linesize[1]` alignment padding.

No exploitable memory safety vulnerability found across the full call chain from `mss2_decode_frame` through all DSP routines.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
