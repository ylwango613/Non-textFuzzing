After completing all analysis passes, I have the complete picture:

**Group 1 (parser.c):** `parse_opus_ts_header` initializes `GetByteContext` at `start+1` with `buf_len = buf_size - i`; the minimum detection index is `i=1`, giving exactly `buf_size-1` bytes from `start+1` — no off-by-one.  The bounds check at line 76 (`bytestream2_tell + payload_len_tmp > buf_len`) correctly constrains the return pointer and `payload_len`. The final `poutbuf = buf + header_len` / `poutbuf_size = buf_size - header_len` are properly bounded.

**Group 2 (parse.c / ff_opus_parse_packet):** Code 3 CBR non-self-delimiting with excess padding yields `frame_bytes = end-ptr-padding < 0`. The division/modulo checks fail to catch negatives, so negative `frame_size` values reach the decoder. However, `bits_init8` receives `unsigned int byte_size = (unsigned)(-127) = 4294967169`, which exceeds `INT_MAX/8` and returns `AVERROR_INVALIDDATA` before any buffer access — the OOB pointer is never dereferenced.

**Group 3 (self-delimiting CBR, signed overflow):** The check `pkt->frame_count * frame_bytes + padding > end - ptr` could theoretically overflow if `padding ~ INT_MAX`. That would require ~8.4 million bytes of lacing metadata in a single packet — impossible in Ogg (≤65025-byte packets) or MPEG-TS Opus encapsulation.

**Group 4 (ff_opus_parse_extradata):** Channel map bounds verified: `extradata_size >= 21 + channels` enforced; `channel_reorder_vorbis` only invoked when `channels ≤ 8`; `default_channel_map` only used when `channels ≤ 2`.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
