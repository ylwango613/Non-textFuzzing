After comprehensive analysis:

**`utvideodsp_init.c`** (target): 45-line CPU-dispatch stub — checks `av_get_cpu_flags()` and assigns two function pointers. Zero memory allocation, zero data processing, no buffers touched. Inherently clean.

**`utvideodsp_rvv.S`**: RVV assembly correctly implements the C reference. Decrement-then-check loop structure handles all height≥1 cases correctly. For height=0 the outer loop would not be entered in practice since FFmpeg validates dimensions before reaching this point.

**`utvideodec.c`** (call chain context):
- `slice_end` from the bitstream is validated with `bytestream2_get_bytes_left(&gb) < slice_end` before being used, bounding `max_slice_size` to actual available data.
- `max_slice_size += 4*avctx->width` (line 715): both operands are tightly bounded (slice size by remaining packet bytes; width by codec caps), no exploitable overflow.
- `av_fast_malloc(…, max_slice_size + AV_INPUT_BUFFER_PADDING_SIZE)`: correctly oversized.
- `bswap_buf` write size `(slice_size + 3) >> 2` words ≤ `max_slice_size + 3` bytes, always within the allocated buffer.
- `av_calloc(avctx->width + 8, …)` for `c->buffer`: `av_calloc` has internal overflow protection.
- Pack-path 8-byte unaligned stores: AVFrame linesizes are always ≥16-byte aligned, making partial-group OOB impossible in practice.
- `restore_rgb_planes` / `restore_rgb_planes10` operate on properly allocated AVFrame plane buffers; all address arithmetic is within bounds.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
