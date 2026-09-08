After complete analysis of all 1359 lines of `huffyuvdec.c` in four sequential read passes, plus examination of related headers and utilities:

**Batch 1 (lines 1–400):** `read_len_table` has proper `i + repeat > n` bounds check; `generate_joint_tables` allocates exactly `5 << VLC_BITS = 20480` bytes covering the three sub-arrays and uses `av_assert0(i < (1 << VLC_BITS))` to guard indices; `read_huffman_tables` / `read_old_huffman_tables` operate on fixed-sized arrays within bounds; `decode_init` allocates `4 * avctx->width + 16` bytes per temp buffer, width validated by `av_image_check_size2` (which rejects w=0 and w×h overflow).

**Batch 2 (lines 400–795):** Pixel-format switch arms are exhaustive with a default AVERROR_INVALIDDATA. Width evenness check for YUV422P prevents sub-minimum width reaching decode. Temp buffer allocation is after all extradata validation.

**Batch 3 (lines 795–1195):** `decode_bgr_1` writes to `temp[0][4*i]` with max i = width−1 → max byte offset `4*width−1`, safely within `4*width+16`. `decode_422_bitstream` accesses `temp[1][i]` and `temp[2][i]` for i < width/2, well within the 4*width+16 allocation. `decode_plane_bitstream` accesses `temp16[0][2*i+1]` for i < width/2, max byte offset `2*width−1`, also safe.

**Batch 4 (lines 1195–1359):** Multi-slice (HYMT) slice boundary check `nb_slices*8LL + slices_info_offset > buf_size−16` is correct. If `slice_size < table_size`, `init_get_bits8` catches negative byte_size and returns AVERROR_INVALIDDATA (verified in `get_bits.h` line 547). All `bswap_buf` calls stay within the `buf_size`-sized allocation.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
