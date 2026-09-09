Now I have the full picture. Let me analyze each critical computation:

**`av_image_check_size2` bounds analysis** (line 301):
```c
stride = 8LL*w + 1024;
if (stride*(h + 128ULL) >= INT_MAX) → reject
```
This limits: `8*w*(h+128) < INT_MAX`, so `w*h ≲ INT_MAX/8`. Therefore `frame_size = row_size * height ≈ w*h/8 < INT_MAX/64 ≈ 33M` — well within `int` range, no overflow possible.

**`encode_init` analysis (lines 53–58)**:
- `row_size = (w + 7) >> 3` — w is bounded to a few million by the stride check, so `w+7` never overflows a signed int.
- `frame_size = row_size * height` — bounded to < INT_MAX/64, no overflow.
- Both allocations checked for NULL.

**`encode_frame` analysis (lines 100–119)**:
- Destination writes: `curr + y * s->row_size` where `y < height` — stays within `[0, frame_size)`.
- `src += src_linesize` — `linesize[0]` is trusted from the encoder framework for AV_PIX_FMT_MONOBLACK.
- XOR loop iterates `s->frame_size` times over identically-sized buffers `prev`/`curr`.
- Output buffer: `deflateBound(zstream, s->frame_size)` is a guaranteed upper bound on compressed output; `total_out <= frame_size + small_overhead << INT_MAX`.

**Conclusion**: All buffer sizes are properly bounded by `av_image_check_size2`'s `stride*(h+128) < INT_MAX` constraint. No integer overflow, no under-allocation, no OOB access.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
