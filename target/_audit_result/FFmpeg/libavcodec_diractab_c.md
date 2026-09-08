After thoroughly reading `diractab.c` (a pure static data file) and tracing every call site in `diracdec.c` that indexes into these tables:

- `ff_dirac_qscale_tab[116]`: all accesses are guarded by `quant <= DIRAC_MAX_QUANT_INDEX-1` (= 115)  
- `ff_dirac_qoffset_intra_tab[120]` and `ff_dirac_qoffset_inter_tab[122]`: also accessed with the same quant ≤ 115 bound, well within their larger sizes  
- In `decode_hq_slice` (line 862): `quant = FFMAX(quant_idx - s->lowdelay.quant[...], 0)` where `quant_idx ≤ 115` and `s->lowdelay.quant` is `uint8_t` (non-negative), so `quant` is bounded to [0, 115]  
- In `decode_subband` (line 740): secondary guard `if (quant > DIRAC_MAX_QUANT_INDEX - 1)` before table access  
- In `decode_ld_picture` (line 793): `quant_base = get_bits(gb, 7)` (max 127), FFMAX clamped, and the subsequent `decode_subband` guards  
- `wavelet_idx` is validated `≤ 6` before indexing `ff_dirac_default_qmat[7][4][4]`

The file itself contains only compile-time constant arrays with no dynamic allocations, arithmetic, or pointers.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
