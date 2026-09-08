After a thorough multi-pass audit of `ac3dec_fixed.c` and all its `#include`d code (`ac3dec.c`, `eac3dec.c`) plus referenced headers and tables, here is my verdict:

**Pass 1 — `ac3dec_fixed.c` (lines 1–246):**
- `scale_coefs()` and `scale_coefs_q2()`: 8-wide unrolled loop called with `len=256`; maximum index is `src[255]`/`dst[255]`, both within the `[7][256]` arrays. No overflow.
- `ac3_downmix_c_fixed16()`: `samples[j][i]` and `matrix[0/1][j]` with `j < in_ch = fbw_channels ≤ 6`, all within bounds.

**Pass 2 — `ac3dec.c` decode_exponents() (lines 317–356):**
- Stack array `dexp[256]`. Maximum writes: `ngrps * 3` where `ngrps` is at most 84 (from `end_freq=253`, `group_size=3`). 84×3 = 252 ≤ 256. No overflow.
- `dexps` write: starts at `start_freq[ch]+!!ch`, max end index = 252. Within `[7][256]`.

**Pass 3 — `decode_band_structure()` (lines 707–753):**
- `bnd_sz[22]`: max `bnd` = `n_subbands - 2`. Max `n_subbands` = 18 (CPL) or 15 (SPX). Max `bnd` = 16. Within `[22]`.
- `memcpy(band_sizes, bnd_sz, n_bands)`: `n_bands ≤ 18` into `cpl_band_sizes[18]` or `spx_band_sizes[17]`. Fine.

**Pass 4 — `decode_audio_block()` / `decode_transform_coeffs()` (lines 1009–1403):**
- Coupling, exponent, and bit-alloc array accesses are all bounded by `AC3_MAX_CHANNELS` and `AC3_MAX_COEFS`.
- `do_imdct()` delay buffer: `ch-1+offset` max = 13 < `EAC3_MAX_CHANNELS=16`.

**Pass 5 — `ac3_decode_frame()` channel/output mapping (lines 1408–1807):**
- `output_buffer[ch+offset]` max index = 13 < 16.
- `extended_channel_map[index]` with `index < nb_channels ≤ EAC3_MAX_CHANNELS=16`.
- `channel_map[extend]` guarded by `extend < channel_map_size ≤ 6`.

**Pass 6 — `eac3dec.c` `ff_eac3_apply_spectral_extension()` `copy_sizes` array:**
- `copy_sizes[SPX_MAX_BANDS=17]`. Maximum wraps bounded by `ceil(extension/diff)`: max extension = 180, min diff = 12, giving ≤ 15 wraps + 1 = 16 sections (< 17). No overflow.

**Pass 7 — `ff_eac3_decode_transform_coeffs_aht_ch()` GAQ mode:**
- `gaq_gain[AC3_MAX_COEFS=256]`. Maximum fills: 85 groups × 3 = 255 entries; reads ≤ 253. No overflow.
- `gbits = bits - log_gain ≥ 3 - 2 = 1`. No negative shift.

All memory accesses are within declared bounds. No externally-triggerable memory safety vulnerabilities were found.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
