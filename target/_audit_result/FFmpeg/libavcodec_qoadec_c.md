I've completed a thorough end-to-end analysis of `qoadec.c` and its call chain. Here is my assessment of every potentially dangerous pattern:

1. **`nb_channels` bounds**: Read as a single byte (0–255), gated by `!nb_channels`, so the effective range is 1–255. The `s->ch[256]` array accommodates indices 0–255, and the loop accesses `s->ch[0]`–`s->ch[254]` at most. No OOB.

2. **`frame->nb_samples` bounds**: Read via `bytestream2_get_be16` (max 65535, always non-negative as `int`). `ff_get_buffer` enforces `frame->nb_samples * avctx->ch_layout.nb_channels <= avctx->max_samples`. No overflow possible with 16-bit × 8-bit products.

3. **Packet-size validation** (lines 113–115): The expression `8 + QOA_LMS_LEN*4*nb_channels + 8LL*ceil(nb_samples/20)*nb_channels` correctly accounts for every byte consumed by subsequent unsafe `bytestream2_get_be16u`/`bytestream2_get_be64u` reads. Maximum value ≈ 6.7 M, safely fits in `int`. No integer overflow in the guard expression itself.

4. **Output buffer write index `si`**: The maximum value of `si` is bounded by `av_clip(sample_index + QOA_SLICE_LEN, 0, frame->nb_samples) * nb_channels + ch - nb_channels`. Since `ch < nb_channels`, this is strictly less than `frame->nb_samples * nb_channels`, the allocated capacity. No OOB write.

5. **Channel layout synchronisation**: When `nb_channels == avctx->ch_layout.nb_channels`, `fill_frame_props` (called inside `ff_get_buffer` → `ff_decode_frame_props`) copies the correct layout from `avctx` to `frame` at line 598 of `decode.c`, so `get_buffer2` always allocates the right number of channels.

6. **LMS array accesses**: `history[]`/`weights[]` accessed only at indices 0–3 (QOA_LMS_LEN−1). No OOB.

7. **`qoa_dequant_tab` index**: `scalefactor = (slice >> 60) & 0xf` → 0–15 (row). `quantized = (slice >> 57) & 0x7` → 0–7 (column). Table is `[16][8]`. No OOB.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
