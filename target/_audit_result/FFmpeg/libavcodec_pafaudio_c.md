All arithmetic checks out:

- `PAF_SOUND_FRAME_SIZE = (256 + 2205) * 2 = 4922`
- `frames = pkt->size / 4922` — safe integer division, guarded by `frames < 1` check
- Per-frame source reads: 512 bytes codebook + 4410 index bytes = exactly 4922 bytes ✓
- Total source bytes: `frames * 4922 ≤ pkt->size` ✓
- `cb[*src++]` — `*src` is `uint8_t` ∈ [0, 255], indexing `cb[256]` — always in bounds ✓
- Output buffer: `PAF_SOUND_SAMPLES * frames * 2` int16_t writes = exactly what `ff_get_buffer` allocates for stereo S16 ✓
- `ff_get_buffer` (decode.c:1805) casts `nb_samples * (int64_t)nb_channels` and checks against `avctx->max_samples` before allocating — overflow is caught there ✓

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
