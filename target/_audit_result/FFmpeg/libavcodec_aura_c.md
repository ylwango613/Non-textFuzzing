The key constraint from `av_image_check_size2` (line 301): `stride*(h + 128ULL) >= INT_MAX` rejects oversized dims. With `stride >= 8*w`, this enforces `w*h < ~268 million`, keeping `avctx->height * avctx->width` well within int range — no overflow in the line-52 size check.

Complete analysis of aura.c (107 lines, read fully):

- **Line 52 size check**: `48 + avctx->height * avctx->width` — both operands are validated by `av_image_check_size2` in `avcodec_open2` to be ≤ INT32_MAX with product < ~268M, so no signed integer overflow is reachable.
- **Line 50 delta_table**: `(const int8_t*)buf + 16`, indexed by `val >> 4` and `val & 0xF` (always 0–15), maps to `pkt->data[16..31]`, within the guaranteed ≥48-byte packet.
- **Width=0 / Height=0**: `av_image_check_size2` rejects `w==0 || h==0` → dimensions reset to 0,0 → decode loop body never executes.
- **Negative dimensions**: Negative `int` cast to `unsigned int` exceeds INT32_MAX → rejected by `av_image_check_size2`.
- **Pixel loop bounds**: After passing the size check, `buf += 48` leaves exactly `pkt->size - 48 = height*width` bytes available; the loop reads precisely that many bytes.
- **Linesize adjustment** (lines 89–91): `ff_get_buffer` for YUV422P always pads linesize ≥ width, so `linesize - width ≥ 0`.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
