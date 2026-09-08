After thorough analysis of `hapenc.c` and its complete call chain — including `hap.h`, `hap.c`, `texturedsp.h`, and `imgutils.c` — I have verified:

1. **`tex_size` computation** (`hapenc.c:283-284`): Integer arithmetic `(width/4) * height / 4 * tex_ratio` is bounded by `av_image_check_size`'s stride-based guard `(8w+1024)*(h+128) < INT_MAX`, which caps max tex_size at ~264M — well within `int` and `size_t` bounds.

2. **`pktsize` overflow check** (`hapenc.c:199`): `FFMAX(tex_size, max_snappy * chunk_count) + header_length` — `max_snappy * chunk_count ≈ tex_size * 1.17 ≈ 313M`, which fits in `int`. `ff_alloc_packet` further validates with a negative-size guard.

3. **Chunk offset accumulation** (`hapenc.c:104-105`): `uint32_t compressed_offset` accumulates actual (not max) chunk sizes, total bounded by `tex_size ≤ 264M` — no `uint32_t` overflow.

4. **Snappy output buffer safety**: `chunk_dst + max_snappy` never exceeds allocated packet space since `pktsize` accounts for `max_snappy * chunk_count` worst case, and actual chunk offsets always lag behind max offsets.

5. **`corrected_chunk_count` decrement loop** (`hapenc.c:297-299`): Terminates at `corrected_chunk_count = 1` at minimum (since `tex_size/tex_ratio ≥ 1` is always divisible by 1); no underflow to zero.

6. **`hap_write_frame_header`**: `bytestream2_init_writer` is given `frame_length = final_data_size + header_length`; all writes stay within those bounds.

No externally-triggerable memory safety vulnerabilities were identified in this encoder path.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
