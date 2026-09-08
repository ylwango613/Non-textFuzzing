Now I have enough context for a complete analysis.

**Summary of findings:**

The file `ps_enc.c` is a 121-line HEVC encoder helper for serializing VPS (Video Parameter Set) structures. Analyzing each function:

1. **`write_ptl_layer`** (lines 25–40): Pure `put_bits` serialization; no dynamic allocation; array index `i` bounded by literal 32.

2. **`write_ptl`** (lines 42–64): Loops over `i < max_num_sub_layers - 1`; arrays `sub_layer_profile_present_flag`, `sub_layer_level_present_flag`, `sub_layer_ptl` are all sized `HEVC_MAX_SUB_LAYERS = 7`; `vps_max_sub_layers` is validated by the decoder parser to be ≤ 7, so all accesses stay within bounds.

3. **`ff_hevc_encode_nal_vps`** (lines 66–121):
   - Line 83 has a **logic error**: uses `vps->vps_max_layers - 1` instead of `vps->vps_max_sub_layers - 1` as the loop start (cf. the matching decoder code in ps.c:847). This causes wrong bitstream output but NOT out-of-bounds memory access, because the loop condition `i < vps_max_sub_layers` caps the loop at index ≤ 6, and all three arrays are sized 7. Even if `vps_max_layers > 7`, the start `i = vps_max_layers - 1 ≥ 7` violates the loop condition immediately and the loop never executes.
   - The function is only called from `libavcodec/qsvenc_hevc.c` with a locally-constructed `HEVCVPS` struct containing encoder-controlled values—it is not invoked via a direct crafted-input path.
   - No `malloc/av_malloc/memcpy` calls; the `put_bits` context is bounded by the caller-supplied `buf_size` via `init_put_bits`.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
