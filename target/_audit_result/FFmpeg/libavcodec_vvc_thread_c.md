After a complete multi-pass analysis of `/data/ylwang/non-textfuzz/target/FFmpeg/libavcodec/vvc/thread.c` and all relevant call chains:

- **Allocation in `ff_vvc_frame_thread_init`**: `av_malloc(ft->ctu_count * sizeof(*ft->tasks))` — `ctu_count` is derived from `pps->ctb_width * pps->ctb_height` where both are `uint16_t` bounded by `VVC_MAX_WIDTH/HEIGHT = 25332` divided by minimum CTU size (32), giving max ~627,264. No integer overflow possible.

- **`ctb_addr_in_curr_slice[k]` → `ft->tasks + rs`** in `ff_vvc_frame_submit` and `run_init`: The backing array `pps->ctb_addr_in_slice` is allocated with exactly `ctb_count` entries, values are computed as `ctb_width * ry + rx` (bounded to `ctb_count - 1`), and `ft->ctu_count` is set from the same `pps->ctb_count`. Consistent sizing.

- **`schedule_inter` listener array**: `num_ref_idx_active[lx]` is bounded to max 15 (via `sh_num_ref_idx_active_minus1 ∈ [0,14]` CBS constraint) or `VVC_MAX_REF_ENTRIES = 29` in the non-override path. Both `t->listener[lx]`, `ctu->max_y[lx]`, and `sc->rpl[lx].refs` are all dimensioned `[VVC_MAX_REF_ENTRIES]`. No OOB.

- **`run[stage]`** function pointer table in `task_run_stage`: The do-while loop in `task_run` increments `t->stage` only *after* calling `task_run_stage`; when stage reaches `VVC_TASK_STAGE_LAST` (10), `task_is_stage_ready` returns 0 immediately, preventing another `task_run_stage` call with an out-of-bounds stage index.

- **`score[stage]`** atomic array: All callers pass stages < `VVC_TASK_STAGE_LAST` (10), matching the array size.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
