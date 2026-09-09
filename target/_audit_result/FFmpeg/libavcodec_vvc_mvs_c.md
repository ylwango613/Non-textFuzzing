After exhaustive multi-pass analysis of all 1967 lines of `mvs.c` and the related headers, data structures, and call chains, I have investigated:

1. **`update_hmvp` `memmove`** (lines 1919–1931): Traced all paths for `*num_hmvp - i`. Match-found case keeps `i ≤ *num_hmvp` (after decrement); no-match case exits loop with `i == *num_hmvp` or hits the `MAX_NUM_HMVP_CANDS` reset. No negative `size_t`.

2. **`mv_merge_pairwise_candidate` / `cand_list` bounds**: Spatial gives max 4 candidates (`nbs[]` has 4 entries + B2 only when `num_cands < 4` → saturates at 4). Temporal adds 1 → max 5. Pairwise writes `cand_list[5]` — inside the 6-element stack array. History bounded by `max_num_merge_cand - 1 ≤ 5`.

3. **`pred_flag_to_mode` LUT OOB**: LUT has 9 entries; `pred_flag` is always set from `PredFlag` enum values ≤ 8 via internal logic (not raw bitstream bits).

4. **RPR collocated reference `tab_dmvr_mvf` mismatch**: Explicitly guarded at `refs.c:593` — decoder returns `AVERROR_INVALIDDATA` if collocated ref is scaled.

5. **`sb_temporal_merge_candidate` division by zero** (`num_sb_x = cu->cb_width >> 3 = 0` for 4-pixel-wide CUs): Not reachable — the caller (`merge_data_block`/`ctu.c:1510`) guards with `cu->cb_width >= 8 && cu->cb_height >= 8` before `merge_subblock_flag` can be set.

6. **`TAB_MVF` OOB indexing**: Neighbour coordinates that go negative or out-of-picture are blocked by `cand_left`/`cand_up` flags (initialised in `NeighbourContext` with `checked=1` when the direction is unavailable) before `TAB_MVF` is ever evaluated.

7. **`store_cp_mv` `memcpy`**: `num_cp_mv = motion_model_idc + 1 ≤ 3 = MAX_CONTROL_POINTS`; source and destination both sized for 3 control points.

8. **`ibc_history_candidates` `cand_list` overflow**: `merge_idx ≤ max_num_ibc_merge_cand - 1 ≤ 5`; loop exits when `num_cands > merge_idx`, so max write is `cand_list[5]` — within the 6-element buffer.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
