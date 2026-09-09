I've now read the full file (815 lines) and traced through all relevant call chains. Here is the complete picture:

- `scan8[i]` for `i ∈ [0,15]` produces values in `[12,39]`; `nnzc` is `uint8_t[5*8]=40` — no OOB.
- `scan8[i]` for `i ∈ [16,35]` (used in `h264_idct_add8_altivec`) tops out at 101; `nnzc` is `uint8_t[15*8]=120` — no OOB.
- `log2_denom` is clamped to `[0,7]` by `h264_parse.c:42-44` before these functions are reached; the shift `offset *= 1 << log2_denom` is bounded.
- `VEC_ST` / `DST_LD` operate on the pre-allocated frame plane. `stride ≥ 16` for any valid H.264 frame (minimum 1 MB = 16px wide), so the 16-byte vector stores stay within the allocated row.
- All loop bounds (`i<16`, `i<8`, `size=4 or 8`) are fixed constants, not derived from the bitstream.
- No dynamic memory allocation occurs in any function in this file.
- The deblocking filter callers (`filter_mb_edgev`, `filter_mb_edgeh`) supply `pix` only at internal MB edges, so negative-offset loads (`vec_ld(-3*stride, pix)`) remain within the frame plane.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
