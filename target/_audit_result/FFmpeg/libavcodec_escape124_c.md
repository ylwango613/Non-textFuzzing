Complete analysis done. Here is my full audit:

**`unpack_codebook` (line 93):** `av_malloc(size ? size * sizeof(MacroBlock) : 1)` — protected upstream at line 275 by `cb_size >= INT_MAX / sizeof(MacroBlock)` check before calling. No overflow possible.

**Codebook size for i=1 (line 263):** `cb_size = s->num_superblocks << cb_depth` runs before the overflow guard at line 266. However, since both operands are `unsigned`, this is defined-behavior wraparound in C. The check `s->num_superblocks >= INT_MAX >> cb_depth` correctly triggers on any wrapping case and returns `AVERROR_INVALIDDATA`. The FIXME comment at line 261 acknowledges the ordering, but the logic is sound.

**`decode_macroblock` line 159:** `if (block_index >= s->codebooks[*codebook_index].size || !s->codebooks[*codebook_index].blocks)` — bounds-checks before the array read at line 162. Uninitialized codebooks have `size=0, blocks=NULL` (zero-initialized struct), so the null/size check catches both conditions.

**`insert_mb_into_sb` (lines 165-172):** `index` ∈ [0,15] (4-bit read or loop variable). Worst case: `index=15` → `dst = pixels32 + 15 + 12 = pixels32 + 27`; `dst[4]` = `pixels32[31]`. `SuperBlock.pixels32[32]` has indices 0–31, so `[31]` is the last valid element. No OOB.

**`copy_superblock` frame writes:** `new_frame_data` advances by 8 pixels per superblock column, and by `new_stride * 8 − superblocks_per_row * 8` at each row boundary. Loop runs exactly `num_superblocks = superblocks_per_row × (height/8)` times. Last write reaches `new_frame_data + 7 × new_stride + 7`, which maps to the last row of the last superblock row — within the `ff_get_buffer`-allocated frame.

**`num_superblocks` multiplication (line 64-65):** Integer overflow possible for extreme `avctx->width/height`, but FFmpeg validates dimensions before reaching any codec decoder (and an allocation of that size via `ff_get_buffer` would fail independently).

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
