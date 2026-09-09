I've now completed a full analysis of `pnmdec.c` and its dependencies. Let me summarize what was examined:

**Batch 1 (lines 1–415 of pnmdec.c):** All pixel-format cases, bounds checks at line 66 (preliminary), 137 (per-format binary), 205/235 (YUV420), 269–384 (float). Examined `samplecpy`, PutBitContext text path, per-byte ASCII check at line 149.

**pnm.c / pnm.h:** `ff_pnm_decode_header` — header parsing, `av_image_check_size` call, dimension adjustment for PGMYUV, maxval validation.

**av_image_check_size2:** Constraint is `8*w*(h+128) < INT_MAX`, which bounds `w*h < ~268 million`, safely within 32-bit `int`. This precludes overflow in all downstream `n * height` or `w * h * k` multiplications.

**Key findings:**
- Line 66: `width * height / 8` — no overflow, `w*h < 268M` due to `av_image_check_size`.
- Line 137: `n * avctx->height` — max product ≈ 8×16256 × 16256 ≈ 2.1B, within `int`.
- Lines 205/235: `n * height * 3 / 2` — bounded safely.
- Line 269: `w * h * 12LL` — `w*h` as `int` doesn't overflow, then promoted to `int64`.
- Lines 310/361/384: `w * h * 6`, `w * h * 4`, `w * h * 2` — all within `int`.
- Text PNM path: per-byte bounds check at line 149 prevents OOB reads; PutBitContext bounds writes to `linesize`.
- `pnm_get` uses 31-char stack buffer — safe.
- PAM MONO text path: per-byte check prevents read overrun even if initial check underestimates needed bytes.
- Pixel value arithmetic (`65535 * v`) can overflow `int`, but writes only affect pixel values, not memory layout.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
