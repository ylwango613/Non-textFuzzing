**Analysis complete.** I've done a full read of `h264qpel_template.c` (484 lines) and traced all relevant calling context through `h264qpel.c`.

**Key findings from the audit:**

1. **`tmp` buffer sizing** (`hv_lowpass`): `DECLARE_ALIGNED(16, int16_t, tmp)[SIZE*(SIZE+8)]` allocates 16×24×2 = 768 bytes. The first loop writes 21 rows × 32 bytes = 672 bytes; second loop reads at most 672+16 = 688 bytes. Both are within the 768-byte allocation.

2. **No heap allocations** in the template file — all buffers are either caller-supplied frame buffers (pre-validated by FFmpeg's frame management) or compile-time stack arrays.

3. **`vec_ld(-2, s)` / `vec_ld(30, s)` loads** are standard Altivec over-aligned load+permute patterns; they read full aligned 16-byte blocks and extract the needed bytes via permute vectors. H.264 frame buffers always carry 16-pixel border extension, making these safe.

4. **`src - 2*srcStride`** accesses in `v_lowpass` are the standard 6-tap filter lookahead; the caller guarantees border extension.

5. **Stride parameters** (`srcStride`, `dstStride`, `tmpStride`) all originate from `avframe->linesize`, which is set by FFmpeg's internal validated frame allocation — not directly from compressed bitstream fields.

6. **`align` computation** and the `load_alignment` switch statement cover all alignment cases correctly (11–15 with an extra `srcR3` load); no missing case can cause out-of-bounds.

This file is a pure SIMD arithmetic kernel for PowerPC Altivec H.264 quarter-pixel motion compensation. It contains no external data ingestion, no heap allocation, and no attacker-reachable buffer size arithmetic.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
