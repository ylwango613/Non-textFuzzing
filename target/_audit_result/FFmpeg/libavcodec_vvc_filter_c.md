I've now completed a full multi-pass audit of the file and all related headers, buffer allocation sites, and helper functions. Let me summarize the key investigation areas:

**Batch 1 (lines 1–600):** SAO pixel buffer accesses in `copy_ctb_to_hv`, `sao_extends_edges`, `sao_copy_hor`, `sao_restore_vb`. The `edges[]` guards prevent negative-index accesses. Virtual-boundary positions are multiples of 8 (enforced by `ph_vb_pos`), so the `(vb_y - y0) >> vs` shift in `sao_restore_vb` produces `dy >= 3` for chroma — no underflow.

**Batch 2 (lines 600–1000):** Deblock BS computation, `vvc_deblock`, `vvc_deblock_subblock_bs`. Buffer indices via `TAB_BS`/`TAB_MAX_LEN` macros are bounded by CTB dimensions. `DEBLOCK_STEP` and grid alignment are consistent.

**Batch 3 (lines 1000–1246):** ALF coefficient/clip lookup, `alf_copy_ctb_to_hv`, `alf_prepare_buffer`, `alf_get_coeff_and_clip`, `alf_filter_luma/chroma/cc`.

Key verifications performed via Grep:
- `ALF_MAX_BLOCKS_IN_CTU = 128×128/4/4 = 1024` exactly matches the stack arrays in `alf_get_coeff_and_clip`.
- `alf_pixel_buffer_v` size is `h × ALF_PADDING_SIZE × ctb_width` bytes; `(border_pixels << ps) ≤ 6 ≤ 8 = ALF_PADDING_SIZE` for all valid bit depths.
- `alf_pixel_buffer_h` accesses at `(border_pixels × ry × w + x) << ps` stay within `(border_pixels × w × ctb_height) << ps`.
- In `alf_prepare_buffer`, `src` pointers use `ry-1` / `rx-1` offsets; these are only dereferenced when `edges[TOP/LEFT] = 0`, which requires `ry > 0` / `rx > 0`, keeping offsets non-negative.
- VVC minimum CTU size is 32; with `h ≥ 32` and `ctb_width ≥ 1`, the `border_pixels²×(1<<ps)` overshoot concern in `alf_fill_border_v` is ≤ 18 bytes < 2×h×ctb_width (≥ 66 bytes of slack).
- `sao_tab` is indexed by `(FFALIGN(width,8)>>3) - 1`; VVC requires picture width ≥ 8 and multiples of 8, so `width ≥ 4` for chroma and the index is always ≥ 0.
- `ff_vvc_alf_class_to_filt_map` has 16 entries; branch guards `ctb_filt_set_idx_y < 16`.
- `alf_ctb_filter_alt_idx` is bounded by `num_chroma_filters - 1`; no OOB into `chroma_coeff[ALF_NUM_FILTERS_CHROMA]`.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
