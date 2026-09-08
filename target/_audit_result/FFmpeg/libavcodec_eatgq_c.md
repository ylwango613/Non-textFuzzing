After thoroughly reviewing all code paths in `eatgq.c` and the relevant supporting functions, I'll summarize my analysis:

**`tgq_decode_block` (lines 65-115):** All block writes use `block[scantable[i]]` where `i ∈ [1,63]` and `scantable = ff_zigzag_direct[64]` maps strictly to [0,63]. The bounds guard at line 73 (`if (i >= 63)`) correctly prevents the case-4→case-0 fallthrough from incrementing `i` to 64 before accessing `scantable[64]`. Exhausted bitstream safely returns zeros via get_bits API.

**`tgq_idct_put_mb` (lines 117-133):** MB coordinates come from a loop bounded by `FFALIGN(avctx->width/height,16)>>4`, and `ff_get_buffer` allocates aligned-dimension frames, so all four 8×8 write destinations are within the allocated frame buffer.

**`tgq_decode_frame` (lines 241-290):** Width/height from stream (uint16_t) are validated by `ff_set_dimensions → av_image_check_size2` which rejects 0, overflowing, or excessively-large dimensions before any allocation or loop.

**Motion vector (lines 183-208):** The bounds check `x < 0 || x + 16 > s->width || y < 0 || y + 16 > s->height` is correct; since `s->last_frame` is always unref'd on dimension change and re-set to the current frame, the reference frame dimensions always match `s->width/s->height`.

**`tgq_calculate_qtable`:** Pure arithmetic on a fixed-size `int[64]` qtable, no external-input-driven size.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
