Now I have the full picture. Let me do a final analysis pass on the critical sections I identified.

**Batch 1 findings (lines 1-141):** `convolve_horiz_mmi` — `src -= 3` pre-adjustment handled by caller's edge emulation; `MMI_ULDC1` at offsets 0-3 reads 8 bytes each, range `src-3` to `src+10`, which covers the 8-tap window (original_src-3 to original_src+4). Loop structure: shared "1:" label is correct for both inner (width) and outer (height) loops. No OOB.

**Batch 2 findings (lines 143-229):** `convolve_vert_mmi` — reads 8 consecutive rows using ptr arithmetic. For the `hv` pass, `temp[64*71]` provides exactly `h+7` rows needed. No OOB.

**Batch 3 findings (lines 230-408):** `convolve_avg_horiz_mmi` and `convolve_avg_vert_mmi` — `MMI_ULDC1` reads 8 bytes but only uses lower 4 (via `punpcklbh`). The upper 4 "extra" bytes are within allocated stack buffers or frame rows and are discarded in computation.

**Batch 4 findings (lines 409-602, macro section):**
- `temp[64 * 71]`: sized for exactly `SIZE=64, h=64, tmp_h=71 → 64*71=4544` bytes — the maximum VP9 superblock height. Valid.
- Filter indexing `vp9_subpel_filters_mmi[TYPE_IDX][mx-1]`: called from `mc_luma_unscaled` with `mx &= 7` then `mx << 1` (values 2-14 → index 1-13 ✓) and from `mc_chroma_unscaled` with `mx &= 15` (values 1-15 → index 0-14 ✓). No OOB.
- `temp1[64*64]` in `ff_avg_8tap_hv`: written and read exactly `SIZE * h ≤ 64*64` bytes. Valid.
- `h` is `bh` from VP9 block size tables, capped at 64 by protocol.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
