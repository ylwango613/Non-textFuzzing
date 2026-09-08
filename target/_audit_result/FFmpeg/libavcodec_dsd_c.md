`dsd.c` is confirmed at 61 lines — a thin wrapper over `swr_alloc_set_opts2` + `swr_init` with no user-controlled sizes. `AV_SAMPLE_FMT_DSD` is 8 bits packed (non-planar), so `ff_get_buffer` allocates `nb_samples * channels` bytes — matching exactly what `repack` writes. The `frame->nb_samples * channels` computation in `dsddec.c` is mathematically bounded by `avpkt->size` (integer division then multiply back, no overflow). All caller paths use `av_fast_malloc` with the recovered product and check the return value. No exploitable memory safety issues found in `dsd.c` or its immediate callers.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
