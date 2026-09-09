After thoroughly reading all 1,996 lines of `/data/ylwang/non-textfuzz/target/FFmpeg/libavcodec/vp9.c` in four batches, plus examining all related header files (`vp9dec.h`, `vp9shared.h`, `vp9.h`, `vp9data.c`) and `vp9block.c` for called functions, I performed the following checks:

**Allocation sizes (update_size, update_block_buffers, vp9_frame_alloc):**
- `av_malloc` for the above-context slab (line 294): arithmetic promotes to `size_t` before the `sb_cols *` multiplication due to `sizeof` operands; no overflow on 64-bit.
- `av_mallocz` for `block_base` (line 349): `sizeof(int16_t)` causes promotion to `size_t`; can theoretically wrap on 32-bit at extreme dimensions (65536×65536) but `av_malloc_array` and the size computation would be the only risk path, which simply fails allocation (ENOMEM) and is properly checked.
- `sz = 64 * s->sb_cols * s->sb_rows` (line 117): max 64×1024×1024 = 67,108,864, fits in `int`; subsequent `sz * (1 + sizeof(VP9mvrefPair))` promotes to `size_t` before potential overflow.

**segmentation_map indexing:**
- `setctx_2d` in `vp9block.c:140` uses unclipped `bw4`/`bh4`, but the segmap is padded to `64*sb_cols*sb_rows` (superblock-aligned grid). All reachable write positions satisfy `(row+bh4-1)*8*sb_cols + col+bw4-1 ≤ sz-1`.
- Cross-frame read in `vp9block.c:119` with `s->sb_cols` (current) applied to REF_FRAME_SEGMAP: protected by `vp9_decode_frame:1684–1688` which unrefs the REF_FRAME_SEGMAP whenever CUR_FRAME dimensions differ from REF_FRAME_MVPAIR.

**Context array writes (above_*, left_*):**
- All `SET_CTXS` writes at `col` up to `n=8` elements: proved `col+7 ≤ 8*sb_cols-1` for any reachable 64×64-block position (`col+4 < cols` guard ensures `col ≤ 8*(sb_cols-1)`).
- `above_mv_ctx`, `left_mv_ctx`, `above_mode_ctx` (size `16*sb_cols`): maximum write index stays within bounds.

**`nb_block_structure` overflow:**
- `ff_vp9_decode_block` is called at most once per 8×8-pixel area (`bwh_tab[1]` returns `{1,1}` for all BL_8X8 partitions). Maximum `nb_block_structure = s->cols * s->rows = buffer size`. No overflow.

**Tile/header parsing:**
- `tile_size` (int64_t) vs `size` (int): comparison is safe; negative `size` is caught.
- `log2_tile_cols`/`log2_tile_rows` bounds prevent oversized `tile_cols`/`tile_rows`; `c_b` arrays are correctly sized.

**memset calls (vp9_decode_frame:1719–1729):** All lengths bounded by `cols ≤ 8*sb_cols` or `sb_cols*16`; within allocated buffer sizes.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
