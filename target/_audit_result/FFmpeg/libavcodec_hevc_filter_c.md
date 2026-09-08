After a thorough multi-pass analysis of all 924 lines of `filter.c` and the related headers/allocator (`hevcdec.c`, `ps.c`, `hevc.h`, `hevcdec.h`, `cabac.c`), here is my summary of what I examined and why no exploitable bug was found:

**Pass 1 (lines 1–265) — copy primitives, `chroma_tc`, `copy_CTB_to_hv`, `restore_tqb_pixels`:**  
- `tctable[54]` indexed via `av_clip(…, 0, 53)` — safe.  
- `betatable[52]` indexed via `av_clip(…, 0, MAX_QP=51)` — safe.  
- `qp_c[]` 14-element table accessed at `qp_i - 30` where `qp_i ∈ [30,43]` — safe.  
- SAO pixel buffer offsets `((2*y_ctb)*w + x) << sh` stay within allocation `(w * 2 * ctb_height) << pixel_shift`: integer arithmetic with HEVC-constrained dimensions (max `w=16384`, `ctb_height≈1024`) keeps product ≈67 MB, well within int32 range and allocation size.

**Pass 2 (lines 266–478) — `sao_filter_CTB`:**  
- `sao_tab[8]` indexed as `(FFALIGN(width,8)>>3) - 1`. Width capped by CTB size ≤ 64 (`log2_ctb_size` checked ≤ `HEVC_MAX_LOG2_CTB_SIZE=6` in ps.c); max index = 7. Safe.  
- `sao_pixel_buffer_h/v` read offsets at `(2*y_ctb±1)*w + x0±1` — guard conditions (`!top_edge`, `!bottom_edge`, `!left_edge`, `!right_edge`) ensure `y_ctb` and `x_ctb` are bounded such that maximum offset < allocation size.

**Pass 3 (lines 479–677) — `get_pcm`, `TC_CALC`, `deblocking_filter_CTB`:**  
- `TC_CALC` clips to `[0, MAX_QP + DEFAULT_INTRA_TC_OFFSET] = [0, 53]` → `tctable[54]` safe.  
- `betatable` access always clipped to `[0, 51]`. Safe.  
- `vertical_bs`/`horizontal_bs` indexed as `(x + y * bs_width) >> 2` where `bs_width = (width>>2)+1`, `bs_height = (height>>2)+1`, allocation = `bs_width * bs_height`; with `x < width` and `y < height`, the index is always within bounds.  
- `get_qPy` called with non-negative pixel coordinates at all call sites.

**Pass 4 (lines 678–924) — `boundary_strength`, `ff_hevc_deblocking_boundary_strengths`, `ff_hevc_hls_filter`:**  
- `ref_idx` values come from `ff_hevc_ref_idx_lx_decode` (returns in `[0, nb_refs-1]`) and `nb_refs` is validated `< HEVC_MAX_REFS=16 = RefPicList.list[]` array size.  
- `tab_mvf` accesses use `min_pu_width` as stride with `x_pu` and `y_pu` derived from pixel coords bounded by image dimensions.  
- `cbf_luma` array accesses in `ff_hevc_deblocking_boundary_strengths` use `xp_tu`/`yp_tu` which are positive (guarded by `boundary_upper`/`boundary_left` checks that require `y0>0`, `x0>0`).

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
