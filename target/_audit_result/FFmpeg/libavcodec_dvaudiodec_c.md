Complete analysis of `dvaudiodec.c`:

**Buffer access check (PAL non-12bit path, line 112):**
- `shuffle[i]` max for i < 1959, PAL non-12bit: `80*53 + 2*36 + 8 = 4320`
- `AV_RB16(&v[4320])` → reads `src[8640..8641]`, 2 bytes past declared `block_size=8640`
- However, `AV_INPUT_BUFFER_PADDING_SIZE = 64` — FFmpeg guarantees all packets have 64 zeroed bytes past the declared size. The 2-byte overshoot falls entirely inside the padding region (offset 8640..8641 < 8640+64). Not exploitable under standard FFmpeg packet allocation.

**Other checks:**
- `shuffle` array (size 2000): max `frame->nb_samples` = 1959 (PAL, case 0, `buffer[0]&0x3f=63`). Loop i < 1959 → all accesses `s->shuffle[i]` are within bounds.
- `dst` output buffer: `ff_get_buffer` allocates exactly `nb_samples * channels * sizeof(int16_t)`. Loop writes exactly `2 * nb_samples` int16_t values. No OOB write.
- `dv_get_audio_sample_count`: reads from `pkt->data+244` — always within the packet (guaranteed ≥ 8640 bytes by the check at line 96).
- 12bit path reads `v[0]`, `v[1]`, `v[2]` — max shuffle for 12bit PAL: `80*53 + 3*36 + 8 = 4356`, then `src[4358]` < 8640. Safe.
- No integer overflows in shuffle computation, no heap allocation with user-controlled sizes.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
