After thorough analysis of `hevcdsp_init_neon.c` and its calling context:

- `ff_hevc_sao_eo_class_decode` reads exactly 2 CABAC bypass bits → returns 0–3, safely within `pos[4][2][2]`
- `(k + sao_left_class) & 31` always produces indices 0–31, within `offset_table[32]`
- `sao_offset_val[k+1]` for k∈{0,1,2,3} accesses indices 1–4 of the 5-element `offset_val[c_idx][5]`
- `put_hevc_qpel_neon[my][mx]` and `put_hevc_qpel_uw_neon[my][mx]` are 4×4 arrays; HEVC qpel fraction is 2-bit (0–3); wrappers are never registered at the `[x][0][0]` slot, so the NULL `[0][0]` entry is never dereferenced
- The file contains no `malloc`/`av_malloc`/`memcpy` calls

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
