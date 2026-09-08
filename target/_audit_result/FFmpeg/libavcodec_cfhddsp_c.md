Now I have the complete picture. Let me do a final analysis before concluding.

The file `cfhddsp.c` is 119 lines of pure DSP computation. Key observations:

**`filter()` potential issue (len < 3):** The epilogue at lines 56-64 uses `i = len-1` (post-loop value). When `len ≤ 2`, the loop doesn't execute, leaving `i=1`, and then `low[(i-2)*low_stride] = low[-low_stride]` — an OOB read. However, every call site in `cfhd.c` explicitly validates `lowpass_width < 3 || lowpass_height < 3` with `AVERROR(EINVAL)` guards (lines 966–972, 1007–1012, 1046–1051) before invoking any of the three filter functions, so `len` is always ≥ 3 when `filter()` is reached.

**Buffer sizing:** `vert_filter` max output index = `(2*lowpass_height-1)*w8 + lowpass_width - 1 ≤ 2*h8*w8 - 1` — exactly fits `l_h[n]` size `2*w8*h8`. `horiz_filter` writes `2*lowpass_width` elements per row with stride `2*w8` over `2*lowpass_height` rows — within `subband[0]`'s allocation.

**`act_plane` / `plane` mismatch in horiz_filter_clip loop:** The loop bound `s->plane[act_plane].height` can differ from the source buffer plane. For YUV422P10, planes 1 and 2 swap but share identical dimensions. For BAYER_RGGB16 all four virtual planes have equal dimensions mapped to plane 0. No cross-dimension mismatch found.

**No malloc/memcpy calls exist in `cfhddsp.c`** — it is pure arithmetic. No integer overflow, no heap allocation, no external data consumption.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
