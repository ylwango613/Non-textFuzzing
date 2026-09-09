I've completed a thorough analysis of `proresdsp.c` and its full call chain. Let me summarize the key findings:

**Batch 1 — `proresdsp.c` (195 lines, read in full)**:
- `prores_idct_10`/`prores_idct_12`: process fixed 64-element `block` and `qmat` arrays; no external-input-controlled indices.
- `prores_idct_bayer_32`: same — 64 fixed iterations.
- `put_pixel_bayer_lin_curve_12`: `seg = av_clip_uint16(…) >> 13` → `seg ∈ [0, 7]`; `lin_curve[seg]` and `lin_curve[seg+1]` (when `seg < 7`) are both within the 8-element `uint16_t lin_curve[8]` array defined in `ProResRAWContext` (prores_raw.h:61).

**Batch 2 — `prores_raw.c` (full decode pipeline)**:
- `lin_curve` is either parsed from the bitstream (exactly 8 × be16) or set to a compile-time default 8-element array. No under-allocation.
- `block[64*16]` (1024 elements): `idx = scan[…] + (block_mask << 6)`. `scan[…] ∈ [0, 63]` (identity-permuted `ff_prores_interlaced_scan`); `block_mask = nb_blocks − 1 ≤ 15`; max `idx = 63 + 15×64 = 1023`. Exactly within bounds.
- `log2_nb_blocks ≤ align ≤ 4` is enforced; no negative shift.
- `n + i` overflow is guarded by `if ((n + i) >= nb_codes) break` before every write.
- `size[3] < 0` check prevents component-size under-allocation.
- `tile_size` validated against `avpkt->size` before `bytestream2_init`.

No externally-triggerable memory-safety vulnerability was confirmed in `proresdsp.c` or its call chain.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
