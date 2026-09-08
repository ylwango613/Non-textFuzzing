Complete analysis summary:

**`gsmdec_data.c`** is a pure static data file containing four read-only lookup tables with no executable code. The accompanying decoder files that consume these tables (`gsmdec_template.c`, `gsmdec.c`, `msgsmdec.c`) were fully analyzed:

- `ff_gsm_dequant_tab[64][8]` — indexed by `maxidx = get_bits(gb, 6)` (0–63). Bounds: exact fit.
- `ff_gsm_requant_tab[4][8]` — first index from `apcm_bits` entries (always 1–3, never 0 or ≥4); second index from `get_bits(gb, frame_bits[i])` bounded by `2^frame_bits[i]-1` (max 7). Safe.
- `ff_gsm_apcm_bits[][4]` — 9 rows (0–8); `mode` validated in `gsm_init()` to stay in `[MSN_MIN_BLOCK_SIZE, GSM_MS_BLOCK_SIZE]` with step-3 constraint, producing modes 0–8 exactly. Safe.
- `ff_gsm_long_term_gain_tab[4]` — indexed by `get_bits(gb, 2)` (0–3). Safe.
- `ref_buf[280]` write range — maximum write at index 279 (fourth sub-frame, offset=3, `dst[36]`), exactly within bounds.
- `init_get_bits` in `ff_msgsm_decode_block` uses fixed size `GSM_MS_BLOCK_SIZE*8`, but actual bit consumption per mode matches `block_align` exactly, so no OOB reads.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
