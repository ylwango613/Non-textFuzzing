After reading all 3182 lines in batches and tracing every allocation, bound check, and array access:

**Fragment count overflow** (`av_image_check_size2` line 301): The stride check `(8*w + 1024) * (h + 128) < INT_MAX` caps each visible dimension to ≈5800 pixels, so `s->width` ≤ 6400, `fragment_width` ≤ 800, and `y_fragment_count = fragment_width * fragment_height` stays well within int32.

**`qr_base[qri+1]` in `init_dequantizer`** (line 431): The Theora loop in `theora_decode_tables` sets `qr_size[0..qr_count-1]` with values ≥ 1 and breaks only when their cumulative sum `qi ≥ 63`. Since `qps[qpi] ≤ 63` always, `init_dequantizer`'s loop always hits its `break` before `qri == qr_count`, so the access to `qr_base[qri+1]` where `qri+1 ≤ qr_count ≤ 63` is within bounds.

**`dct_tokens_base` buffer** (allocated as `fragment_count * 64`): Per-fragment token count across all 64 levels is bounded by 64 (one per active level), and grouped EOB tokens are more efficient than per-fragment EOBs. No overflow.

**`coded_fragment_list` writes**: Bounded by `fragment_count` total entries across all three planes. No overflow.

**All motion_val / all_fragments accesses**: Properly checked against per-plane fragment counts.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
