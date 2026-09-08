After thoroughly analyzing `gsmdec_template.c` and all reachable code (headers, data tables, callers in `gsmdec.c` and `msgsmdec.c`), here is my assessment:

**Analysis summary:**

- `apcm_dequant_add`: `maxidx` = `get_bits(gb, 6)` → 0-63; table `ff_gsm_dequant_tab[64][8]` — in bounds. `frame_bits[i]` values come from static `apcm_bits` tables and are always 1, 2, or 3; `ff_gsm_requant_tab[4][8]` first dim 0-3 — in bounds. `val` is at most `2^frame_bits[i]-1` ≤ 7; second dim 0-7 — in bounds.
- `long_term_synth`: `gain_idx` = `get_bits(gb, 2)` → 0-3; `ff_gsm_long_term_gain_tab[4]` — in bounds. `lag` is explicitly clipped to [40, 120]. With `ref_buf[280]`, at every outer loop iteration `ref_dst` is `ref_buf+120`, `+160`, `+200`, `+240`; `src = ref_dst - lag` reads at most 40 elements, always within the array.
- `short_term_synth`: reads `ref_buf[120..279]` (40 elements for each of 4 sub-segments totaling 160), writes `samples[0..159]` — within the allocated frame.
- `filter_value`: accesses `v[0..8]`; `ctx->v[9]` — in bounds.
- `mode` parameter: for GSM_MS validated at init to [0,8]; `ff_gsm_apcm_bits` has exactly 9 entries — in bounds.

All buffers are fixed-size, all indices are either statically constrained, bit-width-bounded, or explicitly clipped. No integer overflow on allocation sizes, no unbounded copies, no OOB accesses found.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
