I've now completed the full analysis of `h2656_inter_template.c` (577 lines) and its call chains.

**Analysis summary:**

**Batch 1 (lines 1–577): All functions read.**

Key design patterns observed:
- `put_luma_hv`, `put_uni_luma_hv`, `put_uni_luma_w_hv`, `put_chroma_hv`, `put_uni_chroma_hv`, `put_uni_chroma_w_hv` all use stack-allocated `tmp_array[(MAX_PB_SIZE + EXTRA) * MAX_PB_SIZE]` as intermediate scratch buffers, with each row stride = `MAX_PB_SIZE`.
- LUMA_FILTER accesses `src[x-3..x+4]`; CHROMA_FILTER accesses `src[x-1..x+2]`. These assume adequate padding around `src`.

**Bounds-check tracing:**

1. **HEVC path:** `hevc_pel_weight[65]` is a 65-element lookup table; `idx = hevc_pel_weight[block_w]` naturally caps `block_w` ≤ 64 = `MAX_PB_SIZE`. Valid HEVC prediction block widths are `{2,4,6,8,12,16,24,32,48,64}`. Height is similarly spec-constrained. Edge emulation (`emulated_edge_mc`) is triggered precisely when `x_off < QPEL_EXTRA_BEFORE` or near image boundary, ensuring `src[-3]` is always in valid memory.

2. **VVC path:** `MAX_PB_SIZE = 128` (vvc/ctu.h), VVC spec caps prediction blocks at 128. `tmp_array` dimensions match.

3. **Within-row `width` writes:** The inner loop writes `tmp[x]` for `x ∈ [0, width-1]`. Since `width ≤ MAX_PB_SIZE`, the last element in the last row is `tmp_array[(height + EXTRA - 1)*MAX_PB_SIZE + width-1]` ≤ `(MAX_PB_SIZE + EXTRA)*MAX_PB_SIZE - 1`, i.e., within bounds.

4. **Filter coefficient arrays (`hf`, `vf`):** Derived from static lookup tables (`ff_hevc_qpel_filters`, `ff_hevc_epel_filters`), indexed by fractional MV bits — always in-bounds.

**No externally triggerable memory safety vulnerability found** in this template or its call chains for valid bitstream inputs.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
