After thorough multi-pass analysis of the entire `atrac3.c` file (1046 lines) and relevant headers (`atrac.h`, `atrac3data.h`), I verified the following bounds for every critical path:

**decode_bytes**: writes at most `(block_align + 6) / 4 = 1025` uint32_t (4100 bytes) into `decoded_bytes_buffer` allocated as `FFALIGN(block_align, 4) + 64 = 4160 bytes` — no overflow.

**decode_gain_control**: `num_points` from 3 bits = 0..7; `lev_code[7]`/`loc_code[7]` exactly accommodate all 7 entries (indices 0..6) — no OOB.

**decode_spectrum**: `num_subbands` from 5 bits = 0..31; `subband_vlc_index[32]`/`sf_index[32]` cover all accesses; `subband_tab[33]` covers `subband_tab[i+1]` up to index 32; `mantissas[128]` is exactly the maximum subband_size (subband_tab[32]−subband_tab[31] = 128) — no OOB.

**decode_tonal_components**: `component_count >= 64` check at line 379 occurs before first dereference of `components[component_count]`; `cmp->pos = b*64 + get_bits(gb,6)` ≤ 15×64+63 = 1023; `coded_values = FFMIN(1024−pos, coefcount+1)` keeps `pos + coded_values ≤ 1024`; `coef[8]` covers up to 8 coefficients — no OOB.

**add_tonal_components**: `spectrum[pos + j]` is bounded because `pos + num_coefs ≤ 1024 = SAMPLES_PER_FRAME` by construction — no OOB.

**atrac3_decode_init**: `channels` 1..8 checked; `block_align` 1..4096 checked; `q->units` allocated with `av_calloc(channels, sizeof(*q->units))` — no underalloc.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
