After thoroughly reading all of `dsp.c` (280 lines), the full `dsp_template.c` (947 lines), and the included templates (`h2656_sao_template.c`, `h2656_inter_template.c`, `h2656_deblock_template.c`), plus tracing key call sites in `hevcdec.c` and `cabac.c`, here is my analysis summary before the final verdict:

**Group 1 — Filter index accesses (`ff_hevc_qpel_filters[mx]`, `ff_hevc_epel_filters[mx]`):**
- qpel: `mx = mv->x & 3` (line 1733 of hevcdec.c) → always 0–3; array has 4 entries. Safe.
- epel: `mx = av_zero_extend(mv->x, 2 + hshift)` → 2 or 3 bits → 0–3 or 0–7; array has 8 entries. Safe.

**Group 2 — Stack `tmp_array` buffers in HV functions:**
- `(MAX_PB_SIZE + QPEL_EXTRA) * MAX_PB_SIZE = 71 × 64` entries; loop iterates `height + QPEL_EXTRA` rows. Requires `height ≤ 64`. HEVC max CTU is 64×64; block height is bounded by the spec and frame dimensions.
- Same reasoning applies to EPEL HV buffers.

**Group 3 — SAO `eo` index into `pos[eo]`:**
- `ff_hevc_sao_eo_class_decode` reads exactly 2 bypass bits → value ∈ {0,1,2,3}; `pos` array has 4 entries. Safe.

**Group 4 — `dequant` shift arithmetic:**
- For BIT_DEPTH ∈ {8,9,10,12} and log2_size ∈ {2,3,4,5} (spec-guaranteed), `shift` is always non-negative in the first branch and bounded in the second. No UB path reachable with valid bitstream.

**Group 5 — `put_pcm` shift `BIT_DEPTH - pcm_bit_depth`:**
- HEVC SPS constrains `pcm_sample_bit_depth_luma_minus1 < BitDepthY`, so `pcm_bit_depth ≤ BIT_DEPTH` always. No negative-shift UB.

**Group 6 — `transform_rdpcm` / `IDCT` with large `log2_size`:**
- Per HEVC spec and SPS bounds, `log2_size ∈ {2..5}`; callers enforce this before dispatch. No memory safety issue.

No externally-triggerable memory-safety bugs were found in the audited code.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
