Now I have a complete picture. Let me trace the full exploit chain rigorously.

**Key facts gathered:**

1. **Demuxer** (`libavformat/bfi.c:84-85`): `width` and `height` are read via `avio_rl32(pb)` with **no bounds check**.

2. **Decoder init** (`libavcodec/bfi.c:44`): `av_mallocz(avctx->width * avctx->height)` — product computed as `int * int`, which can overflow (UB/CWE-190). E.g., `width=65537, height=65537` → product wraps to `131073` → only 131073 bytes allocated.

3. **Decode loop** (`bfi.c:58`): Same overflow: `frame_end = bfi->dst + avctx->width * avctx->height` → `frame_end` is only 131073 bytes past `bfi->dst`. The decode loop writes into this (small) region — no OOB at this stage.

4. **Final copy loop** (`bfi.c:158-162`): Reads `avctx->width` bytes per row × `avctx->height` rows from `bfi->dst`. With underallocated `bfi->dst` (131073 bytes) but actual dimension needs (~4GB), this would be a massive heap OOB **read** — BUT only if `ff_get_buffer` succeeds first.

5. **Mitigation gate** (`decode.c:1786-1787`): `ff_get_buffer` calls `av_image_check_size2(FFALIGN(w, STRIDE_ALIGN), h, max_pixels, AV_PIX_FMT_NONE, 0, avctx)`. For `w=h=65537`: stride = `8×65544 + 1024 = 525376`; `525376 × (65537+128) ≈ 34.5 billion ≥ INT_MAX` → returns `EINVAL`. **`ff_get_buffer` fails → `bfi_decode_frame` returns early before the OOB copy loop executes.**

6. **Mathematical invariant**: Any `(w, h)` that causes `w*h` to overflow `int` (i.e., `w*h > 2^31`) will also cause `8*w*(h+128) > 2^31`, which is caught by `av_image_check_size2`. The two conditions are inseparable — the mitigation gate covers the full attack surface.

7. **Decode loop boundary checks**: All four opcode cases (`code=0,1,2,3`) have correct boundary checks. `length << lentab[code]` has no shift overflow (max `length=65535`, max shift=2 → max `65535<<2=262140`, fits in `unsigned int`).

8. **Back-chain read bounds**: `dst_offset = dst - offset`; lower bound checked (`dst_offset >= bfi->dst`). Upper bound: `dst_offset` and `dst` advance together, so `dst_offset` stays at most `frame_end - offset < frame_end`. No OOB read.

9. **Palette write**: at most `768/3 = 256` entries × 4 bytes = 1024 bytes into `frame->data[1]` (PAL8 palette = exactly 1024 bytes). Bounded correctly.

**Conclusion**: The integer overflow in `bfi_decode_init` is a real coding defect (CWE-190), but is fully mitigated by `av_image_check_size2` inside `ff_get_buffer` — any dimension pair causing the overflow in `width*height` will also fail the stride check, causing early return before any OOB memory access occurs. No other exploitable memory safety issue is present.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
