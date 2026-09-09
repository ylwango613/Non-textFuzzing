I have now completed a thorough multi-pass analysis of `vbndec.c` and its full call chain:

**Analysis summary:**

1. **Header parsing** (lines 70–97): Magic/major/minor validated; `data_size` compared to exact remaining bytes — a mismatch causes early exit. A negative `data_size` (from `uint32_t→int` sign conversion) can never equal the non-negative `bytestream2_get_bytes_left` result.

2. **Dimension validation** (line 104): `ff_set_dimensions` → `av_image_check_size2` with `AV_PIX_FMT_NONE` falls back to `stride = 8*w`, then enforces `(8*w + 1024)*(h + 128) < INT_MAX`. This limits max dimensions to ~2M×1 or ~1×2M. Consequently, all downstream `linesize * coded_height` products (max ≈ 1.07B for RGBA, ≈ 805M for RGB) are well within `INT_MAX = 2.147B`. No integer overflow.

3. **linesize calculations** (lines 111, 114, 129, 133): All within safe ranges given dimension constraints. DXT1 `linesize = coded_width / 2` exactly represents `(w/4 blocks × 8 bytes/block) / (h/4 block-rows)` — verified against `texturedsp_template.c` which reads exactly `w_block * h_block * tex_ratio` bytes total.

4. **Sufficiency check** (line 144): `image_len < linesize * coded_height` — accurate for all three paths (RAW RGB, RAW RGBA, DXT1/DXT5). No bypass possible.

5. **Output bounds** (lines 155–156, 159–165): `av_image_copy_plane` writes `linesize * frame->height` bytes into an allocated frame of `frame->linesize[0] * frame->height` bytes (where `frame->linesize[0] >= linesize`). Safe. The DXT path's `exec_func` in `texturedsp_template.c` writes exactly to allocated rows with negative stride for flipping — also within bounds.

6. **No compression path** (`decompress()`, line 50): Always returns `bytestream2_get_bytes_left(gb)` for `VBN_COMPRESSION_NONE`; `image_buf` remains NULL; `av_freep(&image_buf)` is a no-op. No memory allocated/freed unsafely.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
