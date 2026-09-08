After thorough multi-pass analysis of `aacps.c` (which `aacps_float.c` includes via `#define USE_FIXED 0` + `#include "aacps.c"`) plus `aacps_common.c`, `aacps.h`, `aacps_tablegen.h`, and `aacpsdata.c`, I verified the following:

**Batch 1 (lines 1–200):** `hybrid2_re`, `hybrid6_cx`, `hybrid4_8_12_cx`, `hybrid_analysis` — all array accesses use hardcoded or constant-bounded dimensions (`in[5][44][2]`, `out[91][32][2]`). The 6-element memcpy from `in[i]+32` to `in[i]` is within the 44-element buffer.

**Batch 2 (lines 200–520):** All `map_idx_*` / `map_val_*` functions operate on arrays sized to `PS_MAX_NR_IIDICC=34`. Indices are hardcoded, no attacker control. `decorrelation()`: `k_to_i` tables (`ff_k_to_i_20`, `ff_k_to_i_34`) max out at 19 and 33 respectively, within `transient_gain[34][32]`. `ap_delay[k][m]` accesses bounded by `PS_AP_LINKS=3` and `PS_MAX_AP_BANDS=50`. `delay[k]` bounded by `PS_MAX_SSB=91`.

**Batch 3 (lines 520–743):** `stereo_processing`: H_LUT tables are `HA[46][8][4]`/`HB[46][8][4]`. Index `iid_mapped + 7 + 23*iid_quant` ≤ 45 for validated `iid_par ∈ [-15,15]`; `icc_mapped` bounded to `[0,7]`. `opd_idx = opd_hist[b]*8 + opd_mapped[e][b]` max = 63×8+7 = 511 — exactly within `pd_re_smooth[512]`. `ff_ps_apply`: `top` from `kx[1]+m[1]` is validated ≤ 64 in SBR header parsing (line 568), so after `top += NR_BANDS[is34]-64`, no OOB in `delay[91]`.

**`ff_ps_read_data`:** `num_env` is at most 4 (from `num_env_tab`), incremented to at most 5 by fake-envelope code; `border_position[PS_MAX_NUM_ENV+1]=[6]` handles index 5. All `H11/H12/H21/H22[2][6][34]` accesses with `num_env_old ≤ 5` are in-bounds.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
