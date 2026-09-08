After reading all 1710 lines in three passes and cross-checking related helpers, here is the summary of my findings:

**Group 1 (lines 1–600) — setup, shader dispatch, buffer allocation:**
- `buf_bar[8]` vs `nb_buf_bar++` accesses: counted carefully — maximum 5 before any reset, stays within 8. Safe.
- `img_bar[37]` vs `ff_vk_frame_barrier` calls: each call adds at most `nb_images ≤ AV_NUM_DATA_POINTERS = 8` entries; two frames at most = 16. Well within 37. Safe.
- `plane_state_size *= context_count` / `slice_state_size = plane_state_size * f->plane_count` (uint32_t math): `CONTEXT_SIZE = 32`, max `plane_count = 4`; would require hundreds of millions of contexts to overflow — unrealistic.
- `remap_data_size = 4 * max_pixels_per_slice * 3 * sizeof(uint32_t)` (uint32_t): overflow requires `max_pixels_per_slice > UINT32_MAX/48` — see Group 3 analysis.

**Group 2 (lines 600–1200) — submit, get_packet, shader init:**
- `pkt->size += sl_len` (line 815): `pkt->size` is `int`, `sl_len` is `uint32_t` from a host-visible GPU buffer. Summing > INT_MAX slices' output would overflow, but this requires >2 GB of compressed FFV1 output from a single frame — not practically triggerable from a crafted media file.
- `rb_off = fd->idx * f->max_slice_count * sizeof(uint32_t)` (line 797): `fd->idx` is bounded by `async_depth = exec_pool.pool_size` (overwritten at line 1554); `f->max_slice_count ≤ MAX_SLICES = 1024`. Product remains safe.

**Group 3 (lines 1200–1710) — init function:**
- Lines 1453–1462, `mw*mh` overflow: `mw` and `mh` are `uint32_t` computed from `avctx->width / num_h_slices`. Their product `pn = mw*mh` uses uint32_t arithmetic and wraps to 0 when both exceed √UINT32_MAX. This results in `max_pixels_per_slice = 2`, making `remap_data_size` tiny (96 bytes/slice). However, triggering this requires float32 pixel format (`GBRPF32`/`GBRAPF32`), remap_mode enabled, and video dimensions ≥ 65537×65537 pixels. Decoded frames from ordinary container formats will never be float32; the attack cannot be triggered by opening a crafted media file in a standard `ffmpeg -i` pipeline.
- `fv->async_depth` option allows INT_MAX from user CLI, but is overwritten at line 1554 before the `av_calloc` allocation. Safe.

**Conclusion:** All potential issues either require encoder-specific conditions (float32 frames, extreme dimensions, explicit remap_mode) that are unreachable from a crafted media file in the standard decoder path, or involve GPU-side memory (not host CPU memory). There are no host-side memory-safety bugs that can be externally triggered by a crafted media file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
