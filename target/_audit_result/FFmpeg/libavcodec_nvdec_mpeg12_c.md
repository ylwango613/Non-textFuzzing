After thoroughly analyzing the file and its full call chain, I've confirmed:

1. **`idct_permutation[i]` loop (lines 89–93)**: `n = s->idsp.idct_permutation[i]` — every permutation type (NONE, LIBMPEG2, TRANSPOSE, PARTTRANS, SIMPLE_MMX, SSE2) produces values strictly in [0, 63] by design (`simple_mmx_permutation` max = 0x3F; SSE2: `(i & 0x38) | perm[i&7]` max = 0x3F). Both `intra_matrix[64]` and `inter_matrix[64]` are safe to index with `n`.

2. **`ff_nvdec_simple_decode_slice` (nvdec.c:1061–1081)**: `av_fast_realloc` with `(nb_slices+1)*sizeof(unsigned)` — signed int overflow at INT_MAX is theoretically possible but practically unreachable; `av_fast_realloc` fails with ENOMEM before any OOB access. `bitstream_len` (`int`) accumulated via `+= size` (`uint32_t`) could overflow into negative, but only affects GPU-side NVDEC operations, not CPU memory safety.

3. **`nvdec_mpeg12_start_frame` field copies**: All fields come from already-validated `MpegEncContext` state, not directly from the raw bitstream. No heap allocation occurs in this function.

4. **Null-ptr safety**: `s->cur_pic.ptr` is guaranteed non-NULL by the MPEG decoder state machine invariants before `start_frame` is invoked.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
