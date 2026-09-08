After reading and analyzing all 1273 lines of `hevc_mc_uni_lsx.c` in four batches, and tracing the complete call chain:

**Batch 1 (lines 1–500):** `common_hz_8t_64w_lsx`, `common_vt_8t_8w_lsx`, `common_vt_8t_16w_lsx`, and wrapper variants. All SIMD loads and stores are aligned to fixed column widths; loop bounds are `height` and `width` from caller. No allocation, no user-controlled index arithmetic.

**Batch 2 (lines 500–1000):** `hevc_hv_8t_8x2_lsx`, `common_vt_2t_24w_lsx`, `common_vt_2t_32w_lsx`, `hevc_hv_4t_8x2_lsx`, `hevc_hv_4t_8x6_lsx`, `hevc_hv_4t_8mult_lsx`. SIMD loads intentionally read 16-byte chunks from 8-byte columns (standard HEVC buffer padding convention). No dynamic allocation.

**Batch 3 (lines 1000–1273):** `hevc_hv_4t_8w_lsx`, `hevc_hv_4t_12w_lsx`, `hevc_hv_4t_16/24/32w_lsx`, and the `UNI_MC`/`UNI_MC_HV` macros instantiating the public entry points. Filter index is `ff_hevc_qpel_filters[mx]` (array size 4) and `ff_hevc_epel_filters[my]` (array size 8). Caller bounds: `mx = mv->x & 3` (0–3) for qpel; `mx = av_zero_extend(mv->x, 2+hshift)` (0–7 max) for epel — both within declared bounds.

**Key findings:**
- Zero dynamic memory allocation in this file.
- All SIMD load/store offsets are compile-time constants.
- All filter coefficient lookups are bounded by caller constraints enforced in `hevcdec.c`.
- `hevc_hv_4t_8w_lsx` silently does nothing for height values ≠ {2, 6, multiple-of-4} — a correctness bug but no memory corruption.
- SIMD 16-byte reads past 8-byte column boundaries are intentional and covered by HEVC reference-frame buffer padding guaranteed by the decoder framework.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
