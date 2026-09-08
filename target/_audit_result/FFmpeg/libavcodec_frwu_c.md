Full analysis complete. Let me summarize what I examined:

**File overview**: frwu.c is a 126-line decoder for "Forward Uncompressed" video. The `decode_frame()` function reads two interlaced fields from the packet and writes them into an AVFrame.

**Security analysis of each path**:

1. **Line 53 — Initial size check** (`avctx->width * 2 * avctx->height + 4 + 2*8`): Signed integer multiplication can overflow for very large width×height (e.g. 32768×32768 → wraps to −2147483648), bypassing the check entirely. **However**, the per-field checks at lines 74 and 78 are independent and correct for these dimensions (min_field_size doesn't overflow at that scale), providing full defense-in-depth. No OOB access results.

2. **Line 68 — `min_field_size` overflow**: For `min_field_size = width * 2 * field_h` to overflow int, the frame would need to be ~4 GB (confirmed mathematically: overflow threshold ≈ 2×INT_MAX bytes of pixel data). `ff_get_buffer` would need to allocate 4 GB of contiguous memory — unreachable on any realistic system. If this overflow occurred, it would bypass the field-size check (line 74) and enable the loop to read past buf_end, but the pre-condition makes it impractical.

3. **Loop body `memcpy` (line 90)** — `memcpy(dst, buf, avctx->width * 2)`: No per-iteration bounds checking, but guarded by the correct pre-loop checks when min_field_size is not overflowed.

4. **`change_field_order=1` edge cases**: With small heights and `change_field_order=1`, `dst` is initialized to `pic->data[0] + 2*linesize` in the field=1 path, but the in-loop reset (`dst = pic->data[0]` on the last iteration) always fires before dereferencing. No OOB write occurs. Additionally, `change_field_order` defaults to 0 and cannot be set from the media file.

5. **`bytestream_get_le32` calls**: All properly guarded by `buf_end - buf < 8` checks.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
