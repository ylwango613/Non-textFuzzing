The analysis is complete. Let me summarize the key findings from my thorough audit:

**Allocations (lines 84–87):**
- `av_calloc(width, h4)` — `av_calloc` uses `size_mult` + `__builtin_mul_overflow`, then `av_malloc` caps at `max_alloc_size = INT_MAX`. If `width * h4 > INT_MAX`, returns NULL (caught at line 88–89).

**Memset at line 304:** `memset(mp->changes_map, 0, avctx->width * avctx->height)` — the int multiplication `width * height` could theoretically overflow, but since `h4 >= height` (h4 rounds up to next multiple of 4), `width * height ≤ width * h4 ≤ INT_MAX` (guaranteed by the successful allocation). No overflow possible here.

**`changes_map` accesses (lines 221–223):** `changes_map[y0+x+width*{1,2,3}]` — the allocation uses `h4 = (height+3)&~3`, so there are always 0–3 extra zero-filled rows. All accesses remain within `width * h4`.

**`hpt` indexing (lines 225, 241–244):** Index formula `((y/4)*width + x)/4` — with `x < width` and `y/4 < h4/4`, the maximum index is strictly less than `(h4/4) * (w4/4)` = hpt allocation size. Mathematically verified.

**`codes[]` array (line 149):** Bounded by `codes_count ≤ 15 < MAX_HUFF_CODES = 16`. Safe.

**Recursion in `mp_get_code` (lines 133–151):** Depth bounded by `max_codes_bits ≤ 15`. No stack overflow.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
