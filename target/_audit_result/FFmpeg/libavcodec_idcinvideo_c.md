**Analysis complete.** I've carefully read all 253 lines of `idcinvideo.c` and traced every memory-touching operation:

- `huff_build_tree`: `huff_nodes[prev]` has `HUF_TOKENS*2 = 512` slots. With 256 leaves (worst-case adversarial histogram), the algorithm creates at most 255 internal nodes, so `num_hnodes` peaks at 511 — the last valid index. No OOB write possible.
- `idcin_decode_vlcs`: `dat_pos >= s->size` gate prevents OOB read on packet data. Frame pixel writes are bounded by `linesize * height`. Child-node indices from `huff_smallest_node` are always within 0..510; a `-1` child terminates the while-loop harmlessly (it becomes a pixel value of 255 via implicit truncation, not a memory access).
- `idcin_decode_init`: validates `extradata_size == 65536` exactly; `histogram_index` accesses bytes 0–65535 exactly within that buffer.
- `memcpy(frame->data[1], s->pal, AVPALETTE_SIZE)`: `s->pal` is `uint32_t[256] = 1024 bytes = AVPALETTE_SIZE`. Exact match, no overflow.
- `max_pixels = 320*240` default cap prevents dimension-based integer overflow in the loop bounds.

No externally triggerable memory safety vulnerability found in this file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
