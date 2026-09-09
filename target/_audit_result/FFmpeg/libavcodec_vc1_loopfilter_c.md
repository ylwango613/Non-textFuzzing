Having read the entire file (1243 lines) and traced the key allocations and access patterns, I have a complete picture. Let me do one final check on the `vc1_filter_line` access extents to confirm bounds analysis.

The filter reads `src[-4*stride]` through `src[+3*stride]`, so ±4 rows around the filter point. All the `dst + N*linesize` invocations stay within the 16-row MB block or in well-padded neighboring areas. The `_base` arrays (`cbp_base`, `ttblk_base`, `is_intra_base`, `luma_mv_base`) each carry a `2*mb_stride` guard prefix, exactly covering the largest backward offsets (`-2*mb_stride`) used in the code. The `fieldtx_plane`/`over_flags_plane` accesses are all gated by `mb_x > 0` and `!first_slice_line` guards that prevent negative indices. No `av_malloc`/`memcpy` with file-controlled sizes exists in this file — it is purely a DSP filter with pre-validated frame geometry.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
