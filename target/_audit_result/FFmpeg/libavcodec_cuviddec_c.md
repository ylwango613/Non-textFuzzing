After a thorough multi-pass review of all ~1800 lines of `cuviddec.c`, including the `cuparse_ext` allocation/memcpy pattern, `key_frame[]` array access paths, `CurrPicIdx`/`picture_index` bounds, FIFO growth arithmetic, and `av_reallocp_array` overflow protection:

- The `cuparse_ext` allocation (lines 1652–1660) correctly sizes the buffer to accommodate `extradata_size` bytes beyond `raw_seqhdr_data`.
- `av_reallocp_array` uses internal `size_mult` overflow protection, ruling out heap underalloc via large `nb_surfaces`.
- `CurrPicIdx` and `picture_index` are bounded by the NVDEC driver to `ulNumDecodeSurfaces = ctx->nb_surfaces`, which is consistent with the `key_frame[]` allocation size.
- The FIFO growth path is protected by the `fifo_size_inc > 0` guard.
- No directly externally-triggerable memory-safety bug survives verification in FFmpeg's own code (the NVIDIA CUVID library handles actual bitstream parsing internally).

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
