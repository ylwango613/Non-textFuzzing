With all source read, I'll now complete the analysis.

**msrle.c analysis (171 lines):**

- Line 89: `int istride = FFALIGN(avctx->width*avctx->bits_per_coded_sample, 32) / 8;` — The multiplication is `int*int`; for bits=24 and a large width, this can overflow. However, `FFALIGN` of a large negative value divides by 8 to produce another large negative `istride`. On line 105, `avctx->height * istride` with a negative `istride` produces a negative product that can never equal `avpkt->size` (always ≥ 2). Constructing a positive-wrapping overflow requires widths ≥ ~10⁹ (e.g., `width=1,073,741,825` for 4-bit gives `istride=4`), but `avcodec_open2` calls `av_image_check_size2` which rejects such extreme widths before any frame decode.
- Lines 114–127 (uncompressed path): `memcpy(ptr, buf, linesize)` where `linesize ≤ istride` for all valid (non-overflowed) dimension combinations: 8-bit `linesize=width ≤ FFALIGN(width,4)=istride`, 24-bit `linesize=width*3 ≤ FFALIGN(width*3,4)=istride`. No OOB write or read here.
- Lines 76–78 (palette init): bounded by `FFMIN(extradata_size, AVPALETTE_SIZE)/4`, safe.
- Line 101: `memcpy(s->frame->data[1], s->pal, AVPALETTE_SIZE)` — palette plane is always `AVPALETTE_SIZE` bytes for PAL8. Safe.

**msrledec.c analysis (265 lines):**

- `msrle_decode_pal4`: All pixel writes guarded by `pixel_ptr >= avctx->width` checks; bytestream2 tracks input exhaustion. No OOB.
- `msrle_decode_8_16_24_32`:
  - `width = FFABS(pic->linesize[0]) / (depth >> 3)` — safe unsigned division.
  - Copy path (lines 176–202): guarded by `output + p2*(depth>>3) > output_end` before any write. `p2` is `uint8_t`-range, depth ≤ 32, product ≤ 1020 — no overflow.
  - Run path (lines 206–241): guarded by `output + p1*(depth>>3) > output_end`. Same bounds.
  - Skip (lines 162–173): `pos >= width` check uses unsigned comparison; negative-wrapped `pos` (after signed overflow) promotes to large unsigned, correctly triggers error return.
  - End-of-line (line 156): resets `pos=0` and recomputes `output` from `line * linesize` — no stale pointer use.
  - `bytestream2_get_le16u` / `bytestream2_get_le32u` (`u`-suffix = no-check) are only used after the `bytestream2_get_bytes_left(gb) < p2*(depth>>3)` guard at line 179. Safe.

**Summary:** `av_image_check_size2` rejects extreme widths before decode, frame allocation failure is properly returned, all input reads use bytestream2 bounds tracking, all output writes are bounded by `output_end`. No practically triggerable memory safety vulnerabilities exist in this file pair.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
