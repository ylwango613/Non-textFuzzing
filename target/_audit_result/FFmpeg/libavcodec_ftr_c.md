Complete analysis done. Confirmed:
- `size` from `ff_adts_header_parse` is a 13-bit ADTS field in `[7, 8191]` bytes; `size * 8` max = 65528, no integer overflow
- `AV_AAC_ADTS_HEADER_SIZE = 7`, confirms lower bound
- `memcpy` source is bounded by `size * 8 <= get_bits_left(&gb)` check (line 99)
- `memcpy` destination (`s->packet`) is properly grown via `av_grow_packet` before use
- `extended_data[ch_offset + ch]` index is guarded by the check `ch_offset + s->frame->ch_layout.nb_channels > avctx->ch_layout.nb_channels` at line 156–157
- copy size `bytes_per_sample * s->frame->nb_samples` matches destination plane size because `frame->nb_samples == s->frame->nb_samples` is enforced at line 150–151
- `aac_avctx[64]` array is protected by the `nb_channels > 64` guard in `ftr_init`

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
