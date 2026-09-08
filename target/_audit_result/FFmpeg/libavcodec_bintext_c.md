I've now read the complete source for `libavcodec/bintext.c`, `cga_data.c` (where `ff_draw_pc_font` lives), `libavformat/bintext.c` (demuxer that builds extradata), and `libavformat/utils.c` (where `ff_alloc_extradata` is implemented). Let me summarize the analysis of each potential vulnerability class:

**Font array OOB read (`ff_draw_pc_font`):** `font[ch * font_height + char_y]` — ch ∈ [0,255], char_y ∈ [0, font_height−1]. Max index = `256 * font_height − 1`. Custom-font buffer size = `font_height * 256` bytes. Last valid index = `font_height * 256 − 1`. Exactly fits; no OOB.

**Extradata size check integer overflow:** `(!!(s->flags & BINTEXT_FONT)) * s->font_height * 256` — font_height ∈ [0,255], max product = 65280; total check value ≤ 65330. No 32-bit overflow.

**Negative extradata_size in demuxer:** `fontheight` declared as `char` (possibly signed), but `xbin_probe` validates `d[9] > 0 && d[9] <= 32` (unsigned comparison, so only 1–32 is accepted). `ff_alloc_extradata` also guards with `size < 0` returning `AVERROR(EINVAL)`. No exploitable path.

**Sanity check integer overflow in `decode_frame`:** `(width/8) * (height/font_height) / 256 > buf_size` — for the product to overflow 32-bit it requires width×height > 16 GB, guaranteeing `ff_get_buffer` fails with ENOMEM before any write occurs.

**Frame pixel write boundary:** `draw_char` guards with `s->y > avctx->height − s->font_height` (ensured ≥ 0 by `decode_init`'s min-resolution check). After each character, x/y advancement uses strictly checked boundary logic. `s->font` is always non-NULL after successful `decode_init`.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
