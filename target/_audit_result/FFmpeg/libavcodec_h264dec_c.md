I have completed a thorough multi-pass analysis of `/data/ylwang/non-textfuzz/target/FFmpeg/libavcodec/h264dec.c` and its key callees, including:

- `ff_h264_alloc_tables` (lines 187–259): All integer multiplications (`big_mb_num`, `row_mb_num`, `y_size`, `yc_size`) remain within `int` range because `av_image_check_size` limits `mb_width * mb_height < ~2^20` before this code runs. Even if `row_mb_num * 8` were to overflow with extreme `thread_count`, `av_calloc` → `size_mult` detects the overflow and returns NULL → ENOMEM, never an underalloc.

- `h264_export_enc_params` (lines 878–910): `nb_mb = mb_height * mb_width` is bounded to ~1 M; `block_idx` and `mb_xy` accesses are within their respective allocations (verified by tracing the qscale_table pool sizing in h264_slice.c:169,252).

- `is_avcc_extradata` (lines 951–973): Reads `AV_RB16(p)` before the bounds check on each loop iteration (potential 2-byte OOB read), but packet data is always padded with `AV_INPUT_BUFFER_PADDING_SIZE` bytes of zeros, making this non-exploitable.

- SPS fallback at line 762: `init_get_bits8(&tmp_gb, nal->raw_data + 1, nal->raw_size - 1)` return value is unchecked. With `raw_size == 1` (empty SPS body), `bit_size = 0` → SPS parse fails gracefully. UNCHECKED_BITSTREAM_READER reads from padding bytes, not NULL.

- Reference list management: `ref_count` is capped at 31 (field) / 15 (frame), well within the 48-entry `ref_list` array.

- Slice queue management in `decode_nal_units` / `ff_h264_queue_decode_slice`: `nb_slice_ctx_queued` is bounded by `nb_slice_ctx` at all access points; the swap logic at lines 2206–2209 is correct.

- `dc_val` pointer offsets: All offsets (`y_size + mb_stride + 1`, `+ big_mb_num`) are proven to stay within the `yc_size`-sized allocation for all dimension combinations that pass SPS validation.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
