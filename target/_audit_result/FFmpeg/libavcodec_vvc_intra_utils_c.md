I now have a complete picture of the vulnerability. Let me write up the final analysis.

**Key finding confirmed:**

`angles[]` in `ff_vvc_intra_pred_angle_derive` has exactly 31 elements (indices 0–30). For the negative wide-angle horizontal modes branch (`pred_mode <= 0`), the index formula is `idx = INTRA_HORZ - 2 - pred_mode = 16 - pred_mode`. VVC wide-angle mapping (`ff_vvc_wide_angle_mode_mapping`) for a 4×128 ISP luma CU (wh_ratio=5, min=50) can produce `pred_mode = -15` (idx=31) and `pred_mode = -16` (idx=32) — both out-of-bounds.

The path `ff_vvc_need_pdpc(mode=-15) → ff_vvc_nscale_derive(mode=-15) → ff_vvc_intra_pred_angle_derive(-15)` (intra_utils.c:50) hits this OOB before any protective assertion. The garbage angle value then flows into `ff_vvc_intra_inv_angle_derive` (potential div-by-zero, `av_assert2` disabled in production) and into the prediction loop in `pred_angular_h` where it inflates `pos`, making `idx = (pos>>5)+ref_idx` arbitrarily large and causing OOB pixel buffer reads.

## VULN: VVC intra_pred_angle_derive OOB read via wide-angle mode −15/−16
- **漏洞类别**: memory-safety
- **函数**: ff_vvc_intra_pred_angle_derive()
- **行号**: 177-183
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted VVC media file
- **外部触发路径**: ffmpeg -i <crafted.vvc> -f null - → ff_vvc_decode_frame() → ff_vvc_reconstruct() → FUNC(intra_pred)() [intra_template.c:615, ff_vvc_wide_angle_mode_mapping() → mode=-15 or -16] → ff_vvc_need_pdpc(mode=-15) [intra_template.c:620] → ff_vvc_nscale_derive(mode=-15) [intra_utils.c:71] → ff_vvc_intra_pred_angle_derive(-15) [intra_utils.c:50] → angles[31] OOB read [intra_utils.c:183]; also triggered directly in prepare_intra_edge_params() [intra_template.c:516] and pred_angular_h() [intra_template.c:958]
- **描述**: `ff_vvc_intra_pred_angle_derive` (intra_utils.c:167–170) declares `static const int angles[31]` (valid indices 0–30). In the third branch (pred_mode ≤ 0, line 177): `idx = INTRA_HORZ - 2 - pred_mode = 16 - pred_mode`. For `pred_mode = -15`, idx = 31; for `pred_mode = -16`, idx = 32 — both out-of-bounds. These modes are reachable: `ff_vvc_wide_angle_mode_mapping` (intra_utils.c:197–218) maps original angular modes 51→−16 and 52→−15 when `nh > nw` and `wh_ratio = 5` (e.g., a 4×128 ISP luma CU: cb_height=128, cb_width=4 → |log2(128)−log2(4)| = 5, `min = 60 − 2×5 = 50`). No protective assertion exists in `ff_vvc_intra_pred_angle_derive` itself; `ff_vvc_nscale_derive`'s `av_assert0` does not fire because mode −15/−16 satisfies both `mode < INTRA_LT_CCLM` and `!(mode > INTRA_HORZ && mode < INTRA_VERT)`. The garbage angle returned is subsequently passed to `ff_vvc_intra_inv_angle_derive` (potential integer division by zero when garbage value is 0; `av_assert2` is disabled in production at ASSERT_LEVEL ≤ 1) and used as `dp` in `pred_angular_h` where `pos += dp` per row rapidly overflows, making `p = left + y + ((pos>>5)+ref_idx)` read far outside the allocated pixel edge buffer.
- **触发条件**: 攻击者构造一个包含 ISP（Intra Sub-Partitions）亮度编码单元的畸形 VVC 比特流，使 CU 长宽比达到 4:128（或类似）使 wh_ratio=5，并将 intra_luma_pred_mode 编码为 51 或 52；经过 CABAC 解码后，wide-angle 映射产生 mode=−16 或 −15，触发越界读取。
- **安全影响**: 最坏情况：(1) 读取 `.rodata` 段越界数据作为角度值，导致后续像素缓冲区 OOB 读取（信息泄露，可能披露相邻堆内存内容）；(2) 若越界读回值为 0，`ff_vvc_intra_inv_angle_derive` 执行整数除零（UB，通常为 SIGFPE），或者通过极大 `pos` 使 `p` 指针越过映射区域触发 SIGSEGV，最终确定性崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
