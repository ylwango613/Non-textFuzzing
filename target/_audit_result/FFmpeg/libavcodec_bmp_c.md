After thorough multi-pass analysis of all code paths:

**Group 1 (lines 50–140, header parsing):** Raw `bytestream_get_*` reads without `GetByteContext` bounds. The bitfield path reads up to 15 bytes past the minimum declared `buf_size`, but `AV_INPUT_BUFFER_PADDING_SIZE = 64` guarantees exactly this slack on every `avpkt->data` buffer. Not exploitable.

**Group 2 (lines 211–225, bounds check):** `n = ((avctx->width * depth + 31) / 8) & ~3`, then `n * avctx->height > dsize`. Both multiplications are potentially signed-overflow territory, but `ff_set_dimensions` calls `av_image_check_size2(..., AV_PIX_FMT_NONE, ...)`, which derives `stride = 8*w + 1024` (conservative, pix_fmt-agnostic) and enforces `stride*(h+128ULL) < INT_MAX`. Since `n ≤ stride`, this invariant guarantees `n * avctx->height < INT_MAX` for all accepted dimensions. The overflow path is provably unreachable.

**Group 3 (lines 317–326, depth=4 decoder):** The inner loop writes `2*n` bytes to `ptr` per row. `n ≈ width/2` (padded), so `2*n ≈ width`. Frame linesizes from `ff_get_buffer` are aligned to at least 32 bytes, always ≥ `2*n`. No OOB write.

**Group 4 (lines 241–273, palette):** `colors` is bounded by `min(256, 1<<depth)`. Writes to `p->data[1]` capped to index 255 * 4 = bytes 0–1023, exactly matching the `memset(p->data[1], 0, 1024)` at line 244. No overflow.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
