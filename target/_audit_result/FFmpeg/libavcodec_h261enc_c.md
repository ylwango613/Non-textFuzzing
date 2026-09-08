Based on my complete analysis of `h261enc.c`:

- This is a **pure encoder** (401 lines). No heap allocation occurs within the file itself.
- **`h261_encode_motion`** (line 146–150): `h261_mv_codes[MV_TAB_OFFSET + val]` — the table has 64 entries (indices 0–63). H.261 constrains motion vectors to [-16, +15] full-pixels, meaning half-pixel internal values are [-32, +30] and MV differences are [-31, +31], all within the indexed range. No OOB.
- **`ff_h261_mba_bits[s->mb_skip_run]`** (line 258): table has 35 entries; max skip run within a GOB (33 MBs max) produces index ≤ 32, within bounds.
- **`vlc_lut[run][level + H261_MAX_LEVEL]`** (line 210): guarded by the explicit range check on line 208–209 before the access.
- **`h261_encode_init_static`** table writes: `ff_h261_tcoeff_run` max = 26 (≤ H261_MAX_RUN=26), `ff_h261_tcoeff_level` max = 15 (= H261_MAX_LEVEL), so `vlc_lut[26][30]` is the extreme access — within `[27][32]`. `UNI_AC_ENC_INDEX(26, 79)` = 3407 < 8192. All in bounds.
- No parsing of attacker-controlled bitstreams; motion vectors are computed by the encoder's own motion estimation, not read from external data.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
