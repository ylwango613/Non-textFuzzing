After reading all 886 lines of `wavarc.c` in two batches and cross-checking related headers, I performed the following targeted checks:

**Batch 1 (lines 1–600):**
- `wavarc_init`: `nb_samples` → max 640 / 570 / 256; `max_framesize = nb_samples * 16` ≤ 10240; `av_calloc(max_framesize + 64, 1)` — no overflow.
- `decode_0cpy`: `s->nb_samples = FFMIN(640, get_bits_left(gb) / bits)` — hard cap at 640; accesses `samples[ch][n]` n < 640. Fine.
- `decode_1dif`: `case 7: s->nb_samples = get_bits(gb, 8)` → 0–255; accesses `samples[n + 4]` n < 255 → max index 259 within int[640]. Fine.
- `decode_2slp`: `case 8: nb_samples = get_urice(); if (nb_samples > 570U) ...` — validated; accesses `samples[n + 70]` max n=569 → index 639 in int[640]. Fine.
- `ac_read_model`: `start/end` are 8-bit (0–255), `s->model[start]` with start up to 255 in uint8_t[256]. Fine.

**Batch 2 (lines 600–886):**
- `decode_5elp`: `case 11: nb_samples validated ≤ 570`; `ac_out[n]` n < 570 in int[570]. Fine.
- `order` check: `if ((unsigned)order > FF_ARRAY_ELEMS(s->filter[ch]))` — FF_ARRAY_ELEMS = 70; writes `filter[ch][0..69]`. FIR inner: `samples[n + 70 - o - 1]` min=0, max=638. Fine.
- `do_stereo` (all call sites): `s->samples[ch][nb_samples + n]` max 570+69=639, `s->pred[ch][n]` max 69 in int[70]. Fine.
- `ac_map_symbol`: idx starts at 255, decrements while `prob < freqs[idx]`; since `freqs[0]=0` always after `ac_init_model`, `prob < 0` is false for uint16_t — loop terminates at idx≥0, no underflow.
- Bitstream buffer copy: `buf_size ≤ max_framesize - bitstream_size`; memmove guard ensures write never exceeds `max_framesize + AV_INPUT_BUFFER_PADDING_SIZE`. Fine.
- Output copy: `s->samples[ch] + s->offset` then `src[n]` n < nb_samples; all accesses within int[640] for all codec tags.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
