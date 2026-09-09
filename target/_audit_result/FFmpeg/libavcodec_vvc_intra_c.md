After fully reading all 755 lines of `intra.c` in two passes and tracing all relevant supporting files, here is my analysis summary before issuing the final verdict:

**Checks performed:**

1. **`rem6`/`div6` array OOB read (lines 346-347, `derive_scale`)**: `qp = tb->qp + addin` where `addin` can be 1 when `sh_dep_quant_used_flag && !ts`. For bit_depth=16 (`qp_bd_offset=48`), max `qp = 63+48+1 = 112`, which would be past the end of the size-112 arrays. However — `sps_map_pixel_format()` at `ps.c:40-64` explicitly rejects all bit depths other than 8, 10, and 12 with `AVERROR_INVALIDDATA`. Max reachable bit_depth = 12 → max qp = 63+24+1 = 88 < 112. **Not reachable.**

2. **`scale_clip` memset negative-size trap (lines 270-274)**: `memset(p, 0, sizeof(*p) * (w - nzw))` where `nzw = size_t(max_scan_x + 1)`. If `nzw > w`, unsigned wrapping produces a huge length. Analysis of `init_residual_coding` shows `log2_zo_tb_width = FFMIN(log2_tb_width, 5)`, so scan positions `xc < 2^log2_zo_tb_width ≤ tb_width`, thus `max_scan_x < w` always. **Not reachable.**

3. **`derive_scale_m` index -1 (line 370)**: `ids[...][...][FFMAX(log2_tb_height, log2_tb_width) - 1]` could produce -1 for a 1×1 TB. VVC minimum TB sizes (luma ≥ 4×4, chroma ≥ 2×2 for 4:2:0) guarantee `log2 ≥ 1` for at least one dimension. **Not reachable.**

4. **`ilfnst_transform` bounds (lines 69-131)**: Diagonal-scan coordinates bounded to `[0, n_lfnst_size-1]`; LFNST gated on `min_lfnst ≥ 4`; all coefficient array accesses in-bounds.

5. **`itx[trv/trh][log2 - 1]` function pointer tables**: Only called when width/height > 1, so log2 ≥ 1, index ≥ 0; max log2_tb_width = 6, index 5 = `VVC_N_TX_SIZE - 1`. **Safe.**

6. **IBC (`intra_block_copy`, `ibc_fill_vir_buf`)**: Bitwise-AND masking guarantees `ref_x` and `ref_y` stay within IBC virtual buffer bounds; `rw = FFMIN(w, ibc_buf_width - ref_x)` prevents overflow in the copy. **Safe.**

7. **`vvc_predict_palette` copy**: Source buffer `tb->coeffs` (int array, `w*h` elements = `4wh` bytes) vs. copy size `(w << ps) * h` bytes (at most `2wh` for 10-bit). **Safe.**

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
