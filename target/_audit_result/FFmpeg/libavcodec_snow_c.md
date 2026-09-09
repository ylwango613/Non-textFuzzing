Having now read all 662 lines of `snow.c` and cross-checked the key callees (`snowdec.c`, `snow_dwt.c`, `snow.h`, `av_image_check_size2`, `av_calloc`/`size_mult`, `ff_slice_buffer_init`, `set_blocks`, `unpack_coeffs`, `decode_subband_slice_buffered`), here is my finding summary:

**Allocation targets in `ff_snow_common_init` (snow.c:519–523):**
- `width * height` computed as `int×int` before `av_calloc` — theoretically could wrap to a small positive, but `av_image_check_size2` in `avcodec.c` enforces `8·w·h < INT_MAX` globally before codec init, capping the product well below overflow.
- `((width+1)>>1) * ((height+1)>>1) + 1` similarly protected.

**`ff_snow_alloc_blocks` (snow.c:171–184):**
- `w * h` as int multiplication: with width≤65532 (checked in `decode_header`) and height bounded by `av_image_check_size2`, `w·h ≤ ~1M`, well below INT_MAX. No overflow path.
- `sizeof(*s->block) << (block_max_depth*2)`: `block_max_depth` validated to 0 or 1 by bitstream; result ≤ `4·sizeof(BlockNode)` ≈ 48. Safe.

**`ff_snow_common_init_after_header` scratchbuf (snow.c:547):**
- `FFMAX(linesize[0], 2·width+256) * 7 * MB_SIZE`: linesize[0]=0 on first call (empty frame), so picks `2·width+256`. Max possible linesize is `width+255` (256-byte alignment), which is ≤ `2·width+256`. Computed product ≤ `131320·112 ≈ 14.7M` — no overflow, allocation always sufficient.

**`x_coeff` allocation (snow.c:590–591):**
- `(b->width+1)·b->height+1`: finest subband ≈ `(width/2)·(height/2)` ≈ 67M with bounded dimensions; fits in int. `unpack_coeffs` writes at most `(w+1)·h+1` entries, exactly matching allocation.

**`mc_block` stack buffers (snow.c:225–226):**
- `tmpIt[64·(32+8)]`, `tmp2t[3][2560]`: block dimensions bounded to ≤16 via `block_max_depth` and clipping; maximum row advances safe.

**`set_blocks` / `decode_q_branch` (snow.h:405–428, snowdec.c:304–368):**
- Block array indices bounded by `b_width·b_height·4^block_max_depth` with boundary guards (`b_x+1>=b_width` etc.) preventing OOB pointer dereference.

**`decode_subband_slice_buffered` physical line index:**
- `y·stride_line + buf_y_offset` with DWT invariant ensures maximum physical row < `plane.height = line_count`. No OOB into `buf->line`.

**`block_state` accesses:**
- `s_context ≤ 6` (BlockNode.level ∈ {0,1}), all accesses well within `block_state[4224]`.

**`av_calloc` overflow protection:**
- Uses `size_mult` with `__builtin_mul_overflow` — any negative-wrapped int passed as `nmemb` becomes a huge `size_t`, triggering NULL return, which is caught by callers.

After reading and cross-referencing every allocation, index calculation, and memory access path through the complete file, no externally-triggerable memory-safety vulnerability survives all existing guards.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
