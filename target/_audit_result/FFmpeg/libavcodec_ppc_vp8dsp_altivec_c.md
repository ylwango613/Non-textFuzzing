Based on the complete analysis:

**Group 1 (lines 1–149): `put_vp8_epel_h_altivec_core`**
- `LOAD_H_SUBPEL_FILTER(mx-1)` accesses `h_subpel_filters_inner[mx-1]` and `h_subpel_filters_outer[(mx-1)>>1]`. In the calling path (vp8.c:1844), `mx = (mv->x * 2) & 7`, always 0–7. When mx=0 the no-filter `[0][0]` slot is called, so H-filter functions only receive mx=1–7 → indices 0–6 against 7-element arrays. All valid.

**Group 2 (lines 274–301): `EPEL_HV` stack buffer**
- `tmp[(2*WIDTH+5)*16]` bytes. For VTAPS=6, the inner H-pass writes `(h+5)×16` bytes; safe boundary is `h ≤ 2*WIDTH`. VP8 block heights by width: 16-wide → h≤16 (16≤32 ✓); 8-wide → h≤16 exactly (2×8+5=21 rows fits h+5=21) ✓; 4-wide → h=4 (4+5=9 < 13 rows) ✓. All instantiations are exactly sized or over-sized.

**Group 3 (lines 303–327): `put_vp8_pixels16_altivec`**
- Loop processes 4 rows/iter. VP8 always passes h=8 or h=16 for 16-wide blocks (multiples of 4). No over-read.

**Group 4: Filter coefficient arrays**
- `h_subpel_filters_inner[7]`, `h_subpel_filters_outer[4]`, `v_subpel_filters[7]` are constant-size; all access patterns are strictly bounded by bitstream-constrained mx/my (0–6 index).

All buffer sizes are compile-time constants calculated to correctly accommodate the maximum VP8 block dimensions. No external attacker-controlled value flows directly into a buffer-size or index computation within this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
