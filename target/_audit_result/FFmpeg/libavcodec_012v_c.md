The check at line 301 is definitive: for any `w` where `8*w + 128*8 >= INT_MAX` (i.e., `w >= ~2^28 - 1`), `av_image_check_size2` returns `AVERROR(EINVAL)` and `ff_get_buffer` fails — so the decoder exits at line 65 before reaching any memcpy. This closes the integer-overflow path I traced through the stride calculation.

All other potential issues I investigated:

- **`width * 8 / 3` overflow** (line 46): requires `width >= 2^28`; blocked by `av_image_check_size2` in `ff_get_buffer`.
- **`height * stride` overflow** in size check (line 58): for widths where `ff_get_buffer` can succeed, stride = `width * 8 / 3` stays well within int range, so the product doesn't overflow.
- **memcpy OOB read from y_temp / u_temp / v_temp** (lines 130–132): these 6/3/3 element stack arrays are only read with `width - x` elements after an early loop break; I traced all four early-break conditions and confirmed that for any `width >= 6` where `ff_get_buffer` succeeds, the minimum valid stride (`width * 8 / 3 >= 16`) prevents the break from occurring at `x = 0`.
- **Stride recalculation via packet** (lines 53–56): the guard `avpkt->size / avctx->height * 3 >= width * 8` ensures the packet-derived stride is always ≥ the default stride, so it cannot produce a stride that triggers the early-break OOB path.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
