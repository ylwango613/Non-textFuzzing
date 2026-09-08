I have now read all 2746 lines of `hevc_lpf_sao_msa.c` in five batches and examined the key supporting context (struct definition, calling site in `filter.c`, macro header). Let me consolidate findings:

**Batch 1 (lines 1–500): `hevc_loopfilter_luma_hor_msa`**  
All pointer arithmetic (`p3 = src - stride<<2`, etc.) is within HEVC-spec-bounded frame buffers. SIMD loads `LD_UH` read 16 bytes per row, consistent with 8-pixel luma width + alignment padding. `tc[0]`/`tc[1]` and `p_is_pcm[0]`/`p_is_pcm[1]` accesses are exactly sized by the HEVC spec call convention. No OOB write paths.

**Batch 2 (lines 500–1000): `hevc_loopfilter_luma_ver_msa` + `hevc_loopfilter_chroma_*`**  
`src -= 4` then `LD_UH8` loads 8 rows × 16 bytes. Frame stride is always ≥ 16-byte aligned in FFmpeg. Negative-offset accesses (`p3[-4]`, `p3[-1]`) are intentional in-frame references, bounded by the HEVC CTB neighbourhood. No allocation, no integer overflow.

**Batch 3 (lines 1000–1500): SAO band filter functions**  
`LD_SB(sao_offset_val + 1)` loads 16 bytes starting at `sao_offset_val[1]`. The array is `int16_t[5]` (10 bytes), so the load reads 8 bytes past the 5-element array boundary. However, the immediate next operation is `__msa_pckev_d(offset_val, offset_val)` which discards the upper 8 bytes, and then `__msa_pckev_b` further narrows to 4 bytes (indices 1–4). **Critically**, the "overread" lands inside the same `SAOParams.offset_val[3][5]` struct field — consecutive channel arrays are contiguous — so no page boundary crossing occurs in any realistic allocation layout. Same pattern in `hevc_sao_band_filter_8width_msa` and `hevc_sao_band_filter_16multiple_msa`. Functionally harmless; no write corruption.

**Batch 4–5 (lines 1500–2746): SAO edge filter functions + dispatch wrappers**  
All edge filters start with `LD_SB(sao_offset_val)` (16-byte load from a 10-byte array), immediately narrowed to 8 bytes by `__msa_pckev_b`. Actual filter index table lookups (`vshf_b` with indices 0–4 derived from the `edge_idx = {1,2,0,3,4,0,...}` table) only access result bytes 0–4 (valid). The SAO loop-iteration loop bounds (`height -= 2`/`height -= 4`) match the HEVC constraint that CTB dimensions are multiples of 8 (≥ 8), so no infinite-loop path. Width dispatch in `ff_hevc_sao_band_filter_0_8_msa` / `ff_hevc_sao_edge_filter_8_msa` passes a width that is already a multiple of 16 to the 16-multiple functions, preventing overstore. No heap allocation, no attacker-controllable size arithmetic, no OOB writes.

**Summary**: No memory-safety vulnerability with an external attack trigger path was identified. All computations operate on properly padded frame buffers; the only overreads (`LD_SB` past `sao_offset_val`) fall within the parent struct's contiguous storage and the out-of-bounds bytes are arithmetically discarded before any computation.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
