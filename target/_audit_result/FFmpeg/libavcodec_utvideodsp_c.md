The file is only 86 lines. I've now read the full `utvideodsp.c` and traced both call sites in `utvideodec.c` (lines 761–763 and 776–778), where `restore_rgb_planes` and `restore_rgb_planes10` are called with frame buffers allocated by `ff_thread_get_buffer` and with `avctx->width` / `avctx->height` as the loop bounds.

Both functions in `utvideodsp.c`:
- Perform no memory allocation
- Perform no `memcpy` / `memmove`
- Read and write only within `src[i]` for `i ∈ [0, width)`, advancing by `linesize` each row
- Contain no untrusted size arithmetic, no `av_malloc`, no integer overflow paths
- The 10-bit variant receives `linesize / 2` before the call, which is the correct stride for `uint16_t *` pointer arithmetic

The `width`/`height`/`linesize` values passed to these functions originate from `avctx` and the frame allocator — not directly from the compressed bitstream — so they are not attacker-controlled in a way that bypasses frame buffer bounds.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
