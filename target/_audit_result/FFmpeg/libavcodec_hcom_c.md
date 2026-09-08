**Analysis summary:**

- `dict_entries` is `AV_RB16` → max 65535; `dict_entries * 4 + 7` max = 262147, no overflow in int.
- `av_calloc(dict_entries, sizeof(HEntry))` — `av_calloc` itself checks for overflow internally.
- Extradata bounds: `extradata_size >= dict_entries * 4 + 7` guarantees the last `AV_RB16` read at `extradata + 6 + 4*(dict_entries-1) + 2` stays in bounds.
- Huffman traversal: non-leaf nodes have both `.l` and `.r` validated to be in `[0, dict_entries-1]`; leaf nodes (`.l < 0`) only use `.r` as a delta value (not as an index). The root entry 0 is forced to be non-leaf. Every index used to access `s->dict[]` was validated at init time.
- `frame->nb_samples = pkt->size * 8` with the `pkt->size > INT16_MAX` guard; the counter `n` is incremented at most once per bit, so `n <= pkt->size * 8`, never exceeding the allocated buffer.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
