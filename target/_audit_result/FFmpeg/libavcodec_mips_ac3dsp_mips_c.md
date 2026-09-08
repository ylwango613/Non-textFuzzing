After reading the full file (424 lines, single pass sufficient) and tracing all callers and related tables, here is the complete analysis:

**Function-by-function findings:**

- **`ac3_bit_alloc_calc_bap_mips` (L68–143)**: Inline asm indexes `bap_tab` with a value clamped to [0,63] via `shll_s.w` (saturating shift) then `+32`. `bap_tab` (`ff_ac3_bap_tab`) has 64 entries. The C-level table lookups (`ff_ac3_bin_to_band_tab[start]`, `ff_ac3_band_start_tab[++band]`) use `start`/`band` from AC-3 spec-constrained decoder state (validated before reaching this call at `ac3dec.c:1307`). No OOB possible.

- **`ac3_update_bap_counts_mips` (L145–205)**: Each `bap[]` byte is shifted left 1 and used as a halfword offset into `mant_cnt[16]` (32 bytes). `ff_ac3_bap_tab` max value is **15** (verified in `ac3tab.c`), so max offset = 30, within the 32-byte array. This function is only called from the encoder (`ac3enc.c:1335`) with internally-computed bap values from that same table — not from attacker-controlled stream data.

- **`float_to_fixed24_mips` (L210–275)**: `len` is `size_t` (unsigned); a value < 8 would cause underflow wraparound and infinite OOB loop. However, all callers pass values that are multiples of 16 or 256 (`s->fbw_channels * 16` in `ac3enc_template.c:320`, `chan_size * (s->channels + cpl)` in `ac3enc_float.c:44`). These are encoder-side calls driven by channel layout configuration, not by attacker-controlled media file fields.

- **`ac3_downmix_mips` (L277–403)**: Explicitly commented out at L418 (`//c->downmix = ac3_downmix_mips;`). Dead code — unreachable.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
