Having thoroughly read and analyzed all relevant files, I'll now summarize my findings:

**Files analyzed:**
- `gsmdec.c` — main decoder entry points
- `gsmdec_template.c` — core decode logic (included twice for BE/LE variants)
- `msgsmdec.c` — Microsoft GSM variant
- `gsmdec_data.h` / `gsmdec_data.c` — `GSMContext` struct definition and all lookup tables
- `gsm.h` — constants (`GSM_BLOCK_SIZE=33`, `GSM_MS_BLOCK_SIZE=65`, `MSN_MIN_BLOCK_SIZE=41`, `GSM_FRAME_SIZE=160`)

**Key analysis results:**

1. **`ref_buf[280]` bounds** — `ref_dst = ctx->ref_buf + 120`; 4 sub-frames × 40 samples → writes to `ref_buf[120..279]`. `apcm_dequant_add` writes `dst[0], dst[3], ..., dst[36]` with max offset 3, so max index at last sub-frame = `240 + 3 + 36 = 279`. All within bounds.

2. **`long_term_synth` src pointer** — `lag = av_clip(lag, 40, 120)`; at worst `src = ref_buf + 0`; reads 40 elements → `ref_buf[0..39]`. Fine.

3. **Table lookups** — `maxidx = get_bits(gb, 6)` → 0–63 (table is `[64][8]`); `gain_idx = get_bits(gb, 2)` → 0–3 (table is `[4]`); `frame_bits` values are 1–3 from `apcm_bits[][]`; `val = get_bits(gb, frame_bits[i])` ≤ 7; `ff_gsm_requant_tab[3][7]` max value is 7. All within their respective table bounds.

4. **Output sample buffer** — `frame->nb_samples` set to `avctx->frame_size` (160 or 320) before `ff_get_buffer`; writes stay within that allocation.

5. **`block_align` validation for MS-GSM mode** — enforced in `gsm_init` to range [41, 65] in steps of 3; mode index `(65 - block_align) / 3` → 0–8, valid for `ff_gsm_apcm_bits[9][4]`.

6. **Input size check** — `buf_size >= avctx->block_align` is checked before decode; `ff_msgsm_decode_block` uses `GSM_MS_BLOCK_SIZE * 8` for `init_get_bits` but the actual bit consumption per two frames exactly matches `block_align × 8` bits; FFmpeg's mandatory `AV_INPUT_BUFFER_PADDING_SIZE` covers any speculative reads.

No exploitable memory-safety issues found.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
