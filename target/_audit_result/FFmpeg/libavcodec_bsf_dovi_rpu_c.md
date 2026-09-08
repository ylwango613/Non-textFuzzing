Based on my comprehensive analysis of:
- `/data/ylwang/non-textfuzz/target/FFmpeg/libavcodec/bsf/dovi_rpu.c`
- `/data/ylwang/non-textfuzz/target/FFmpeg/libavcodec/dovi_rpudec.c`
- `/data/ylwang/non-textfuzz/target/FFmpeg/libavcodec/dovi_rpuenc.c`
- `/data/ylwang/non-textfuzz/target/FFmpeg/libavcodec/dovi_rpu.c`
- `/data/ylwang/non-textfuzz/target/FFmpeg/libavutil/dovi_meta.c`
- Supporting headers and CBS infrastructure

Key findings from the investigation:

1. **`nal->data_size - 2` potential underflow**: `data_size` is `size_t`, but CBS H265 always guarantees `data_size >= 2` (via `h2645_parse.c:634` `if (nal->size <= 0 || nal->size_bits <= 0) continue` and the `get_bit_length` min_size=2 check). With `data_size == 2`, `rpu_size = 0` is caught by `ff_dovi_rpu_parse`'s `rpu_size < 5` guard before any pointer is dereferenced.

2. **Buffer size in `ff_dovi_rpu_generate()`**: The `buffer_size += 160` for the fixed RPU mapping section covers approximately 159 bytes of maximum content (header, pivots, NLQ pivots, partition golombs, NLQ coefficients). Combined with `av_fast_padded_malloc`'s guaranteed 64-byte padding, actual usable space is 224+ bytes — sufficient.

3. **Ext block array bounds in `parse_ext_blocks()`**: The explicit checks `if (ext->num_static >= FF_ARRAY_ELEMS(ext->dm_static))` and `if (ext->num_dynamic >= FF_ARRAY_ELEMS(ext->dm_dynamic))` enforce the 7-static/25-dynamic limits before any array write.

4. **`ff_dovi_get_metadata()` ext block copy**: `num_static ≤ 7` and `num_dynamic ≤ 25` → combined total ≤ 32 = `AV_DOVI_MAX_EXT_BLOCKS`, exactly fitting the allocated `AVDOVIMetadataInternal` struct.

5. **T35/NAL wrapping allocation sizes**: T35 wrapper needs exactly `rpu_size + 15` bytes (confirmed by bit-level calculation); NAL wrapper `4 + rpu_size * 3/2` is a correct worst-case for emulation prevention expansion.

6. **Integer overflow in `rpu_size + 3`**: `rpu_size` is bounded by `buffer_size` (a few thousand bytes at most), making overflow of `rpu_size + 3` impossible in practice.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
