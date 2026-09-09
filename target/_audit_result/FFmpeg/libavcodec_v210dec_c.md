I've now completed the analysis. Let me summarize the key security-relevant findings:

**Integer overflow in `v210_stride(int width, int align)`** — `aligned_width * 8` could theoretically overflow `int` for very large widths. However, `av_image_check_size2` (called in `avcodec_open2`) enforces `(2w + 1024) * (h + 128) < INT_MAX`, which for V210's pixel format limits `w < ~8.32 million`. At that maximum, `aligned_width * 8 ≈ 66 million`, safely below INT_MAX. No overflow possible.

**`stride * avctx->height` overflow at line 148 and 178** — With large-but-valid dimensions (e.g., w=100000, h=10000), `stride * avctx->height ≈ 2.67 billion` overflows `int` to a large negative number. At line 148 this makes the fallback branch unreachable. At line 178 this causes `psrc += 64` to execute incorrectly — but immediately thereafter line 170 uses `(int64_t)stride * avctx->height` (correct, ≈2.67 billion), which exceeds any valid `avpkt->size` (bounded by `INT_MAX`), causing the function to return `AVERROR_INVALIDDATA`. No memory access with the wrong pointer occurs.

**Odd-width handling** — Manually verified decode_row for widths 1, 3, 5, 7, 11, 13: Y/U/V write counts match exactly the `av_image_fill_linesizes` ceiling-division allocation for every case.

**Strideless path guards** — The `(int64_t)avctx->width * avctx->height > INT_MAX/6` guard before the strideless path prevents any overflow in the subsequent `avctx->width * avctx->height` (int×int) evaluation.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
