After thorough analysis of all code paths in `h264_mp4toannexb.c`:

**Group 1 (lines 84–190): `h264_extradata_to_annexb`**
- `total_size` (uint32_t) accumulates `unit_size + 4` per iteration. SPS capped at 31 units (`& 0x1f`), PPS at 255 (full byte). Max: 286 × 65539 ≈ 18.7MB — well within uint32_t, no overflow.
- `av_assert1(total_size <= INT_MAX - padding)` is a no-op when `ASSERT_LEVEL` is not defined, but the math constraints make this safe regardless.
- `memcpy` destinations (`out + total_size - unit_size - 4`, `out + total_size - unit_size`) are always within the `total_size + padding` allocated region.
- `bytestream2_init` is called after `extradata_size < 7` guard; all `bytestream2_get_byteu` calls are within the 7-byte minimum guaranteed by the check or by padding.

**Group 2 (lines 192–219): `h264_mp4toannexb_save_ps`**
- `size = *dst_size` (int → uint32_t) is safe since `*dst_size` accumulates at most the packet size (bounded by `int in->size`).
- `av_fast_realloc` is called with `size + nal_size + start_code_size`; `nal_size` is bounded by the packet's int size, no uint32 overflow possible.

**Group 3 (lines 221–262): `h264_mp4toannexb_filter_ps`**
- Length-field reads (`buf[i]` for `i < length_size ≤ 4`) rely on `AV_INPUT_BUFFER_PADDING_SIZE = 64` padding — sound FFmpeg convention.
- `(int64_t)nal_size > buf_end - buf` cast correctly handles the case where `buf` advances past `buf_end` after length-field reads.

**Group 4 (lines 283–448): `h264_mp4toannexb_filter`**
- Two-pass (count then copy) with `out_size > INT_MAX - AV_INPUT_BUFFER_PADDING_SIZE` guard before `av_new_packet` prevents OOB write.
- `buf[1]` accesses at lines 372 and 377 without `nal_size ≥ 2` checks read into the packet's padding region — safe by FFmpeg convention, not exploitable.
- `av_assert1(out_size == opkt->size)` verifies the two passes produce identical sizes.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
