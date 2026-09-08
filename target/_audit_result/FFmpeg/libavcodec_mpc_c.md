I have now completed a thorough multi-pass analysis of `mpc.c` and its complete call chain. Here is my finding summary:

**Pass 1 — mpc.c itself (94 lines)**

The two critical array accesses:
- Line 70–76: `(mpc_CC+1)[bands[i].res[ch]]` — only entered when `bands[i].res[ch] != 0`. `mpc_CC` has 19 elements; valid `res` values are -1..17, giving `mpc_CC[0..18]`.
- Line 70–76: `mpc_SCF[bands[i].scf_idx[ch][*] & 0xFF]` — the `& 0xFF` mask unconditionally bounds the index to 0..255; `mpc_SCF` has exactly 256 elements.
- Line 72,75,78: `c->Q[ch][j + off]` — max off = 31×36 = 1116, max j = 35 → index 1151 ≤ MPC_FRAME_SIZE-1 = 1151. Safe.
- Line 87: `c->sb_samples[ch][j][i]` — i ≤ maxband ≤ 31 < SBLIMIT(32), j < 36. Safe.

**Pass 2 — mpc7.c caller validation**

Lines 229–232: explicit range check `if (bands[i].res[ch] < -1 || bands[i].res[ch] > 17)` → return error. `maxbands` validated `< BANDS(32)`, so `mb ≤ 31`. All array accesses in `ff_mpc_dequantize_and_synth` stay in bounds.

**Pass 3 — mpc8.c caller validation**

The `res_vlc` symbols (`mpc8_res_syms`) span 0..16 only. The wrap logic `if(last[ch] > 15) last[ch] -= 17;` keeps `bands[i].res[ch]` in [-1, 15], making `(mpc_CC+1)[res]` access `mpc_CC[0..16]` — well within the 19-element array. `ff_mpc_dequantize_and_synth` is called with `maxband - 1` (not `maxband`), so when mpc8 allows maxband=32, the synthesizer sees 31 — safe. Q and sb_samples bounds hold.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
