After a full multi-pass read of all 2086 lines of `pngdec.c` and tracing the complete call chains, here is my final analysis:

**Batch 1 (lines 1–500)** — `decode_zbuf`, `decode_text_to_exif`, `decode_text_chunk`, filter row code:
- `decode_zbuf` has a hard 16 MB decompression cap (`PNG_ZBUF_MAX_DECOMPRESSED`) and uses `av_bprint` for safe dynamic allocation.
- `decode_text_to_exif`: `exif_len` parsing uses correct `nlen < exif_len` overflow sentinel, including the addition term. The `exif_len - 6` allocation is guarded by `exif_len >= 10`. Inner while loops bound all `*ptr` reads by `++ptr < end`. No OOB write to `exif_data->data` because outer loop iterates exactly `exif_len - 6` times.
- `iso88591_to_utf8`: the `extra > SIZE_MAX - size_in - 1` guard prevents allocation underflow.

**Batch 2 (lines 500–1000)** — IHDR, IDAT setup, palette/trns handling:
- `av_image_check_size` (called with `AV_PIX_FMT_NONE` → uses `8LL*w` stride estimate) enforces `stride*(h+128) < INT_MAX`. This bounds `w` tightly enough that `w * bits_per_pixel` (max 64) does NOT overflow int32 inside `s->row_size = (s->cur_w * s->bits_per_pixel + 7) >> 3`.
- `av_fast_padded_malloc(&s->buffer, ..., s->row_size + 16)` allocates `row_size+16+padding`. `crow_buf = buffer+15`, `crow_size = row_size+1`. zlib outputs exactly `crow_size` bytes to `crow_buf`; all within `buffer+row_size+16` boundary (before padding).
- `decode_plte_chunk`: bounded to `length <= 256*3` and only writes `n <= 256` palette entries.
- `decode_trns_chunk`: strict length checks per color type; `transparent_color_be[6]` not exceeded.

**Batch 3 (lines 1000–1500)** — `handle_small_bpp`, `decode_fctl_chunk`, start of `handle_p_frame_apng`:
- `handle_small_bpp` index arithmetic: for bpp==1 case, `8*i + k - 1` with `width%8 == 0` → loop body never executes. For `width%8 != 0`, indices stay within `linesize[0]`.
- `decode_fctl_chunk`: `cur_w > s->width - x_offset || cur_h > s->height - y_offset` validation with signed int arithmetic correctly rejects invalid frames.

**Batch 4 (lines 1500–2086)** — main chunk loop, transparency expansion, APNG blending:
- Chunk length validation at line 1527 (`length > 0x7fffffff || length + 8 > remaining`) prevents any OOB in chunk body reads.
- Transparency expansion (lines 1778–1809): all three cases (bpp==2, bpp==4, general) traverse right-to-left with destination index always >= source index; no OOB writes to frame buffer.
- `handle_p_frame_apng` memcpy: all three region copies are bounded by `fctl` invariants (`x_offset + cur_w <= width`, `y_offset + cur_h <= height`). The blending `output[10]` local array is safe because `av_assert0(bpp <= 10)` catches violation before the write.
- `iccp_name[82]`: the `while (...cnt++) && cnt < 81` loop writes at most to index 80; `cnt > 80` check triggers error before any possible write to index 81.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
