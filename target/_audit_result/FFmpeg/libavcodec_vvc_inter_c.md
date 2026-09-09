After completing a systematic, multi-batch analysis of all 1015 lines of `/data/ylwang/non-textfuzz/target/FFmpeg/libavcodec/vvc/inter.c` plus all referenced headers, helper files, and DSP templates, here is a summary of every potential concern evaluated, along with the reason each is dismissed:

**BDOF buffer offset (mc_bi, lines 326–357):** `tmp + PROF_TEMP_OFFSET` (+160 elements). BDOF is only armed when `pu->bdof_flag = 1`, and `refine_regular_subblock()` in ctu.c forces `sbw = sbh ≤ 16`. Peak write at `160 + 15×128 + 15 = 2095` versus `tmp[16384]`. The pre-block area used by `bdof_fetch_samples` (`dst – 1 – MAX_PB_SIZE`) reaches `tmp[31]`, comfortably in-bounds. Not vulnerable.

**DMVR SAD buffer (dmvr_mv_refine, lines 784–836):** Same 16-pixel subblock constraint; DMVR fills `pred_h=20, pred_w=20` per reference; `vvc_sad` with max offsets reads up to element 2323 of the 16 384-element `tmp`. Not vulnerable.

**GPM weight table (pred_gpm_blk, lines 600–648):** `gpm_partition_idx = fixed_length_decode(6)` ∈ [0, 63] = `VVC_GPM_NUM_PARTITION`. Block size indices `w = av_log2(cb_width) – 3` and `h` stay in [0, 3] because GPM requires `!is_128` (cb ≤ 64). Not vulnerable.

**ciip_tmp buffer (pred_regular, lines 693–723):** CIIP also requires `!is_128`, so max block is 64×64 luma. Peak byte at `(64–1)×256 + (64–1)×2 + 1 = 16 255 < 32 768`. Not vulnerable.

**DSP put[] index (idx = av_log2(block_w) – 1):** VVC minimum CB = 4 luma → chroma (4:2:0) = 2 → idx = 0. Array declared `[2][7]`; valid indices 0–6. Not vulnerable.

**SCALED_REF_SB integer overflow:** 32-bit intermediate overflow is UB, but the resulting position is always clipped by `emulated_edge_mc`. No OOB memory access. Correctness issue only.

**`put_scaled` / `put_uni_w_scaled` unused `x` offset:** Both functions compute `x = SCALED_INT(ty) – y0` but never use it to stride `tmp`, reading from position `extra_before + j×TMP_STRIDE` regardless of the scaled output row. This produces incorrect motion-compensated pixels for scaled references but does not cause OOB reads (all positions remain well within `tmp_array[1280×128]`). Correctness bug only.

**Large stack allocation in `put_scaled`:** `int16_t tmp_array[1280×128]` = 327 680 bytes. Fixed-size, non-VLA; on standard Linux/Windows (8 MB stack) this is not overflowed. A potential DoS in constrained-stack environments (Android secondary threads, etc.) but not an exploitable memory-corruption primitive.

**`prof_grad_filter` neighbor accesses:** At (x=0, y=0), `p[–1]` = position 159 (left border filled by `bdof_fetch_samples`), `p[–src_stride]` = position 32 (top row filled). At (x=15, y=15), `p[1]` = position 176 (right border) and `p[src_stride]` = position 2208 (bottom row). All filled by `bdof_fetch_samples`. Not vulnerable.

**GPM / DMVR ref_idx and rpl index:** `ff_vvc_luma_mv_merge_gpm` always assigns `pred_flag` ∈ {PF_L0, PF_L1}, so `lx = pred_flag – PF_L0` ∈ {0, 1}; `rpl[lx]` is always valid. `ref_idx` decoded with `nb_refs` as the ceiling. Not vulnerable.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
