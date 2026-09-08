I have now completed a full analysis of `media100_to_mjpegb.c` including:

1. All bytestream2 read/write paths and their FFMIN bounds-clamping in `bytestream2_copy_buffer` and `bytestream2_skip`.
2. The direct `AV_WB32` writes at lines 132–148 — verified that `second_field_offset + 39 ≤ in->size - 284`, always well within the `in->size + 1024 + 64` (AV_INPUT_BUFFER_PADDING_SIZE) allocated buffer.
3. The unsigned wraparound at line 122 (`next_field - bytestream2_tell(&gb)` when `next_field = 0`) — clamped safely by `FFMIN(g->buffer_end - g->buffer, size)` inside `bytestream2_copy_buffer`.
4. The `in->size + 1024` allocation — validated by `packet_alloc`'s check `size >= INT_MAX - AV_INPUT_BUFFER_PADDING_SIZE` before allocation.
5. The `AV_RB32(in->data + i)` at line 115 — loop bound `i < in->size - 4` ensures `i + 3 < in->size`.
6. The `memset` at line 151 — writes into the guaranteed padding region within the total allocation.

The total bytes written to `pb` across both fields is provably bounded by `in->size - 646 + 402 = in->size - 244`, always under the `in->size + 1024` allocation.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
