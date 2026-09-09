After a thorough multi-pass analysis of `/data/ylwang/non-textfuzz/target/FFmpeg/libavcodec/smpte_436m.c` and its complete call chain, here are my findings:

**Key checks verified:**

1. **`smpte_436m_anc_decode_entry` lines 126-131**: `needed_size += anc->payload_array_length` can produce signed integer overflow (e.g., `payload_array_length = 0x7FFFFFF2` → `needed_size = INT_MIN`), bypassing the `needed_size > size` check. However, the secondary check `anc->payload_array_length > AV_SMPTE_436M_CODED_ANC_PAYLOAD_CAPACITY (348)` on line 129 fires for every overflow case (all large values are > 348), preventing the `memcpy` from ever executing with an overflowed size.

2. **`av_smpte_291m_anc_8bit_decode` line 320**: `memcpy(out->payload, payload, out->data_count)` — `data_count` is `uint8_t` (max 255), `out->payload` is `uint8_t[255]`; check on line 318 ensures `data_count + 3 <= sample_count` and validation ensures payload buffer covers `sample_count` bytes. Within bounds.

3. **`av_smpte_291m_anc_8bit_encode` line 418**: `memcpy(out->payload + 3, payload->payload, payload->data_count)` — max write is `3 + 255 = 258` bytes into a 348-byte buffer. Within bounds.

4. **`av_smpte_291m_anc_8bit_extract_cta_708`**: `GetByteContext` provides safe bounded reads; `cc_count <= 0x1F = 31`, so `data_length = cc_count * 3 <= 93`, within the `AV_SMPTE_291M_ANC_PAYLOAD_CAPACITY = 255` caller-allocated buffer.

5. **`av_smpte_436m_anc_append`**: `additional_size` growth is bounded by `anc_packet_count < 65536` and per-packet max size of 362 bytes; total fits comfortably in int32.

All integer overflow candidates in `needed_size` are redundantly guarded by the `CAPACITY` check. All `memcpy` operations are properly bounded by validated constants. The `GetByteContext` API prevents out-of-bounds reads in the CTA-708 extraction path.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
