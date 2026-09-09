After reading the full 1505-line file in three batches and running targeted grep searches, I performed a systematic analysis of every memory-sensitive code path:

**Batch 1 (lines 1–500):**
- `vc1_parse_sprites`: `effect_pcount1` is 4 bits (0–15). Case 7 → writes `effect_params1[0..6]`; Case 14 → writes `[0..6]` and `[7..13]`; Default (including 15) → writes `[0..pcount1-1]`, max index 14 — array declared as `[15]`, all in bounds.
- `effect_pcount2` (16-bit read) is immediately checked `> 10 → AVERROR_INVALIDDATA`, so max 10 writes into `effect_params2[10]` are in bounds.
- `av_clip` for `xoff`/`yoff` in `vc1_draw_sprites`: operator precedence gives `(sprite_width - 1) << 16` as the upper bound, not `sprite_width - (1 << 16)` — correctly positive for all valid sprite widths.
- `sr_rows` allocated at `output_width` bytes; `sprite_h` writes `output_width >> !!plane` bytes — always fits.

**Batch 2 (lines 500–1000):**
- `vc1_decode_init_alloc_tables`: allocations use `mb_stride * mb_height` (both `int`, max ≈ 2050×2050 ≈ 4 MB — no overflow). Larger expressions like `2 * (b8_stride * (mb_height*2+1) + mb_stride * (mb_height+1)*2)` ≈ 33 MB at maximum video dimensions — safe.
- Extradata parsing checks `extradata_size >= 16` before use; `buf2` allocated at `extradata_size + AV_INPUT_BUFFER_PADDING_SIZE`.

**Batch 3 (lines 1000–1505):**
- Slice array growth uses `av_size_mult` (overflow-aware) before `av_fast_realloc`; NULL check on result.
- `slices[n_slices].buf` allocated at `size + AV_INPUT_BUFFER_PADDING_SIZE`; unescape output ≤ input size — destination always sufficient.
- `mby_start` from bitstream (9-bit, 0–511) is always used with `% mb_height`, preventing OOB access into bitplane arrays.
- `n_slices1` is always initialized before the hwaccel field-mode path: set on every code path that sets `buf_start_second_field`, guaranteeing `slices[n_slices1+1]` is always within bounds.
- Slice loop `for (i=0; i<=n_slices; i++)`: accesses `slices[i]` only when `i < n_slices`, and returns `mb_height` without dereference at `i == n_slices`.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
