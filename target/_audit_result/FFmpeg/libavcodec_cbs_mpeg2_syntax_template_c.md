After thorough analysis of `cbs_mpeg2_syntax_template.c` and `cbs_mpeg2.c`/`cbs_mpeg2.h`:

**Key findings examined:**

1. **`picture_display_extension()` (lines 340-345)**: `frame_centre_horizontal_offset[3]` and `frame_centre_vertical_offset[3]` are fixed arrays of size 3. `number_of_frame_centre_offsets` is a `uint8_t` set only in `picture_coding_extension()` to values 1, 2, or 3 — never exceeding the array bound. If `picture_display_extension` arrives without prior `picture_coding_extension`, the context is zero-initialized (via `priv_data_size` zeroing in `ff_cbs_type_mpeg2`) so the loop runs 0 times. Bounded correctly.

2. **`user_data()` allocation (lines 70-78)**: `k = get_bits_left(rw) / 8` — bounded by the actual bitstream buffer size (an `int` return). `av_buffer_allocz(k + AV_INPUT_BUFFER_PADDING_SIZE)` cannot overflow since k ≤ INT_MAX/8.

3. **`extra_information()` allocation (lines 186-196)**: Counts `k` bytes by consuming bitstream markers, then allocates `k + AV_INPUT_BUFFER_PADDING_SIZE`. k is bounded by the bitstream size divided by 9 bits; no integer overflow possible.

4. **`quant_matrix_extension()` wrong field (lines 317-321)**: Writes to `intra_quantiser_matrix[i]` when `chroma_intra_quantiser_matrix[i]` is intended — this is a logic bug, but both arrays are `uint8_t[64]` and i ∈ [0,63], so no memory safety violation occurs.

5. **`cbs_mpeg2_assemble_fragment()` size accumulation (line 372)**: Accumulates `3 + data_size` per unit into `size_t size`. Unit data_sizes are bounded by the input fragment, which itself must fit in memory — no practical overflow path.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
