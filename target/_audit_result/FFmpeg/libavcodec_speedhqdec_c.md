After a complete multi-pass read of all 675 lines and tracing every relevant call path, here is the security assessment:

**Batch 1 (lines 1–196):** `decode_alpha_block` — `i >= 128` guard is evaluated *before* `block[i++]`, so the maximum write index is 127 (within `block[128]`). `decode_dct_block` — `i > MAX_INDEX (63)` is checked before `block[scantable[i]]`; `scantable` values are a permutation of 0–63; `quant_matrix` is 64 elements. No OOB.

**Batch 2 (lines 197–397):** `decode_speedhq_border` — `x = frame->width - 8`; width is guaranteed ≥ 8 and a multiple of 8, so the rightmost pair of 8-pixel DCT blocks falls within `coded_width = FFALIGN(width, 16)` exactly. `decode_speedhq_field` slice-offset loop: `last_offset`/`slice_len` are `uint32_t`, `slice_offsets[]` is `int`. The theoretical overflow path (`last_offset + slice_len > INT_MAX`) would require a ~2 GB packet — impractical. All three guard conditions (`end < start`, `end - start < 3`, `end > buf_size`) are evaluated before pointer arithmetic.

**Batch 3 (lines 399–675):** `speedhq_decode_frame` — `second_field_offset` (AV_RL24) is checked against `buf_size - 3`; buf_size ≥ 4 is pre-validated. Codec init assigns pixel formats only from a fixed set; no external size field drives any allocation. VLC tables are statically allocated and sized.

No practically exploitable memory-safety vulnerability found.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
