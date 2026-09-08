Now I have all the information needed to complete the analysis. The `edge_emu_buffer` is allocated as `alloc_size * EMU_EDGE_HEIGHT` bytes, where `alloc_size = FFALIGN(linesizeabs + 64, 32)` and `EMU_EDGE_HEIGHT = 280`. The buffer access in `mpeg_motion_lowres` reaches at most `18 * linesize + 19 * uvlinesize ≈ 27.5 * linesize`, well within 280 rows. All array indexing is guarded by `av_assert2(op_index <= 3)`, all allocations use error-checked `av_refstruct_pool_get`, the `memcpy` ranges in `ff_mpeg_update_thread_context` copy between identically typed structs, and `nb_mb` multiplication uses bounded values from `av_image_check_size`-validated dimensions.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
