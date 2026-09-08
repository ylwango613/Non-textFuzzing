After reading all 2380 lines in five batches and performing targeted grep verification on every suspicious pattern, my findings are:

**Section-by-section analysis:**

1. **Lines 1–500 (huffman/RLE)**: `huf_build_dec_table` stays within the `HUF_ENCSIZE`-sized `td->he` array (iM capped at `HUF_ENCSIZE-1` by check at line 462). `rle()` bounds-checks both source and destination counters on every iteration.

2. **Lines 500–1000 (PIZ/PXR24/B44)**: `ptr += td->xsize * td->ysize * pixel_half_size` (line 656) and `in = tmp + tmp_offset * td->xsize * td->ysize + ...` (line 671) are all-int multiplications that could theoretically overflow when `xsize × ysize` approaches `INT_MAX/2`. However, `uncompressed_size = xsize × channel_offset × ysize` would be ≥ 4 GB in all those cases — allocation fails first with ENOMEM before the computation is reached.

3. **Lines 1000–1242 (DWA)**: `ac_count > 3LL × td->xsize × s->scan_lines_per_block` guard limits AC buffer; `dc_count == dc_w × dc_h × 3` strict equality check prevents OOB on DC array; `2LL × xsize × ysize > rle_raw_size` guard keeps `ai0`/`ai1` accesses in bounds (verified algebraically for both even and odd `rle_raw_size`).

4. **Lines 1242–1510 (decode_block)**: `data_size <= 0` on `uint32_t` at lines 1280/1322 catches the zero case. Key overflow checks at lines 1303/1328 (`td->xsize × (uint64_t)s->current_channel_offset > INT_MAX`) plus `av_image_check_size2` prevent oversized tiles/scanlines. All `channel_buffer[c]` offsets stay within `uncompressed_size`.

5. **Lines 1571–2082 (decode_header)**: `strcmp` on `gb->buffer` is safe because `avpkt->data` has `AV_INPUT_BUFFER_PADDING_SIZE` (64) zero bytes after `avpkt->size`, guaranteeing null termination. `displayWindow` → `s->w` can overflow signed int, but `ff_set_dimensions` → `av_image_check_size` rejects any out-of-range value.

6. **Lines 2083–2300 (decode_frame)**: `nb_blocks` tile-case integer overflow (line 2219) can produce a negative value when `xdelta/ySize × ydelta/ySize > INT_MAX`. The check `bytestream2_get_bytes_left(gb)/8 < nb_blocks` passes for negative `nb_blocks` (unsigned vs. signed comparison), but `av_realloc_f(s->offset_table, nb_blocks, 8)` with a negative size_t returns NULL → AVERROR(ENOMEM). The `execute2` call with negative count executes zero iterations. No memory corruption occurs.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
