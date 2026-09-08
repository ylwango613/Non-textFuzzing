After thorough analysis of `asv.c` (104 lines of static tables and `ff_asv_common_init`), `asvdec.c`, and `asvenc.c`, here is my complete finding summary:

**Batch 1 — `asv.c` (lines 1–104):**
- Contains only 5 static constant lookup tables and `ff_asv_common_init()`.
- `ff_asv_common_init` computes `mb_width/mb_height` as integer division; no memory allocation, no OOB risk.
- With `avctx->width` bounded by `FF_MAX_DIMENSIONS` (≤ 268,435,456), `width + 15` does not overflow `int`.

**Batch 2 — `asvdec.c` decoder logic:**
- `asv2_decode_block`: `count = get_bits_le(4)` → 0–15; loop `i` up to 15; max scantable index = `4×15+3 = 63`; `permutated_scantable[64]` and `intra_matrix[64]` are both 64-element arrays — boundary is exactly reached but not exceeded.
- `asv1_decode_block`: loop `i` up to 9 during writes (check `i >= 10` gates the error path); max scantable index = `4×9+3 = 39` — well within bounds.
- `decode_frame` line 242: `c->mb_height * c->mb_width * 13LL` — the `int × int` multiply can overflow for mb dimensions > ~46342 (width ≈ 741,457 px), yielding a negative `long long` that bypasses the min-size check. However, the immediately following `ff_get_buffer` call uses `av_image_check_size2` which correctly rejects such dimensions with `AVERROR(EINVAL)` before any allocation — making this non-exploitable.
- `bswap_buf` padding: last `buf_size % 4` bytes in the bitstream buffer may be uninitialized (allocated via `av_fast_padded_malloc`, not zeroed), but the VLC reader treats them as bitstream data — information leak to decoded pixel values only, not a memory-safety issue.

**Batch 3 — `asvenc.c` encoder:**
- Line 300: `c->mb_height * c->mb_width * MAX_MB_SIZE + 3` (all `int`) overflows when `mb_h × mb_w > INT_MAX/705 ≈ 3,046,076` (width ≈ 27,920 px). However, reaching this from a crafted media file requires the decoder to successfully allocate a ~8 × 10¹¹-byte frame first (which fails with ENOMEM), so the encoder path is never reached in practice.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
