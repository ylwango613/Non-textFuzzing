After fully reading `adts_header.c` (84 lines), `adts_parser.c`, `adts_header.h`, `mpeg4audio.h`, `aac_ac3_parser.c`, `aac_parser.c`, and `bsf/aac_adtstoasc.c`, here is the complete analysis:

**What the file does:** `ff_adts_header_parse()` reads a 54-bit ADTS bitstream header into `AACADTSHeaderInfo`. No memory allocation, no memcpy, no buffer indexing.

**Findings examined:**

1. **`bit_rate` integer overflow (line 70):** `size * 8 * hdr->sample_rate / hdr->samples` can overflow uint32_t (max 65528 × 96000 = 6.29 × 10⁹ > UINT32_MAX). However, the overflowed result is only used as codec metadata (`avctx->bit_rate`) — not for any memory allocation or indexing — so it does not constitute a memory-safety vulnerability.

2. **`ff_adts_header_parse_buf` padding:** The function signature declares `buf[AV_AAC_ADTS_HEADER_SIZE + AV_INPUT_BUFFER_PADDING_SIZE]` but `init_get_bits8` is called with only 7 bytes, so actual reads are bounded. All callers either use `AVPacket` data (which carries guaranteed padding) or allocate the padded stack buffer explicitly (`adts_parser.c:33`). No OOB read.

3. **`samples` field:** `(rdb + 1) * 1024` where `rdb` is a 2-bit value (0–3), giving 1024–4096. No overflow, not used for allocation in this file.

4. **`frame_length`:** Mirrors `size` (13-bit, 7–8191). Used in BSF to advance packet pointer with a guarded `pkt->size <= 0` check. No heap corruption path.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
