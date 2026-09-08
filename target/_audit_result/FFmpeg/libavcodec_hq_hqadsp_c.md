**Analysis summary:**

`hq_hqadsp.c` (131 lines) is a pure IDCT DSP implementation:

- **No dynamic allocation** (`av_malloc`/`memcpy` — zero hits confirmed)
- `idct_row`/`idct_col` operate only on fixed offsets within a 64-element `int16_t` block (indices `[0..7]` and `[0*8..7*8]`) — all statically bounded
- `hq_idct_put` writes 8×8 pixels into `dst` supplied by the caller; the block is always `HQContext.block[i]` which is `DECLARE_ALIGNED(16, int16_t, ...)[12][64]` (static, fixed-size)
- The `stride` parameter is `pic->linesize[plane] << ilace` where `ilace ∈ {0,1}` — valid
- `prof_num` out-of-range silently falls back to `hq_profile[0]`, so `slice_off[21]` is sized for the maximum `num_slices=20` across all 22 defined profiles
- All slice boundary/coordinate logic in the caller uses bytestream validators and static perm tables guarded by a `static_assert` on total size

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
