After a comprehensive multi-pass audit of all 1909 lines of `vorbisdec.c`, examining every allocation, array index, loop bound, and size computation:

- All `av_malloc`/`av_calloc`/`av_malloc_array` calls use overflow-safe allocators with inputs that are bounded by the bitstream field widths (e.g., `codebook_count ≤ 256`, `ptns_to_read ≤ 65535`, `x_list_dim ≤ 250`, `audio_channels ≤ 255`, block sizes ≤ 8192).
- `VALIDATE_INDEX` / `GET_VALIDATED_INDEX` macros guard every codebook/floor/residue/mapping index derived from the bitstream before use.
- Stack arrays `floor1_Y[258]`, `floor1_Y_final[258]`, `floor1_flag[258]` are sized generously above the computed `x_list_dim ≤ 250`.
- The `lsp` buffer of `(order + 1 + max_codebook_dim)` floats is provably large enough for the worst-case write in the floor0 decode loop.
- `classifs` accesses are bounded by `ptns_to_read * audio_channels`.
- The `res_chan` uninitialized-read path is blocked by the `ch_left > 0` guard at line 1723.
- `FASTDIV` via `ff_inverse` is exact for all reachable VLC code values (≤ 65535 < 16909559), keeping `vqclass` within `[0, classifications-1] ⊂ [0, 63]`.
- All `memcpy` sizes in the overlap-add section are proven to fit within their respective buffers.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
