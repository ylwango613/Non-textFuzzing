I have completed my analysis. The key finding is a stack out-of-bounds read in `hevc_intra_pred_angular_upper_32width_msa` / `hevc_intra_pred_angular_lower_32width_msa` when invoked from `ff_intra_pred_8_32x32_msa`.

**Root cause**: `ff_intra_pred_8_32x32_msa` (line 2452–2460) allocates `top_array[2*32+1]` = 65 bytes and sets `top = top_array + 1`, giving valid indices `top[-1..63]`. At line 3073 it dispatches to `pred_angular[3]` = `hevc_intra_pred_angular_upper_32width_msa` for angular modes. Inside that function, at the 16th loop iteration with angle=32 (mode 34): `idx0=31, idx1=32`, and the SIMD loads `LD_UB(ref + idx0 + 33)` = `LD_UB(top+63)` reads `top[63..78]` (15 bytes OOB), and `LD_UB(ref + idx1 + 33)` = `LD_UB(top+64)` reads `top[64..79]` (all 16 bytes OOB). The generic template-based path (`pred_template.c`) correctly allocates 145-byte buffers; the MSA hand-rolled version does not.

## VULN: Stack OOB Read in MIPS MSA HEVC 32x32 Steep Angular Intra Prediction
- **漏洞类别**: memory-safety
- **函数**: hevc_intra_pred_angular_upper_32width_msa() / hevc_intra_pred_angular_lower_32width_msa()
- **行号**: 1224-1335 (upper), 1652-1762 (lower); triggered from ff_intra_pred_8_32x32_msa() lines 2452-2460 + 3073-3074
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 4.3 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N)
- **严重程度**: Medium
- **攻击向量**: crafted media file (HEVC bitstream)
- **外部触发路径**: ffmpeg -i <crafted_hevc_file.hevc> -f null - → avformat_open_input() → hevc decode loop → intra_pred[3]() = ff_intra_pred_8_32x32_msa() → s->hpc.pred_angular[3]() = ff_pred_intra_pred_angular_3_msa() → hevc_intra_pred_angular_upper_32width_msa() [mode 31-34] or hevc_intra_pred_angular_lower_32width_msa() [mode 2-5]
- **描述**: `ff_intra_pred_8_32x32_msa()` (libavcodec/mips/hevcpred_msa.c:2452) allocates `top_array[2*32+1]` = 65 bytes (`top = top_array+1`, valid range `top[-1..63]`) and `left_array[2*32+1]` = 65 bytes. It then dispatches to the 32-width angular predictor via `s->hpc.pred_angular[3]`. Inside `hevc_intra_pred_angular_upper_32width_msa`, the main loop iterates 16 times with `angle_loop` incrementing by `angle` each step; for angular mode 34 (angle=32) at the final iteration, `idx0=31` and `idx1=32`. The SIMD loads `LD_UB(ref + idx0 + 33)` and `LD_UB(ref + idx1 + 33)` resolve to `LD_UB(top+63)` and `LD_UB(top+64)` respectively — each reading 16 bytes — causing 15 and 16 bytes of out-of-bounds stack reads. The OOB bytes are incorporated into the HEVC intra prediction interpolation math and written verbatim to the decoded pixel buffer. The generic template path (`pred_template.c`) allocates 145 bytes, avoiding this bug; only the MSA-specific replacement functions are vulnerable.
- **触发条件**: 攻击者构造一个 HEVC 视频文件，其中包含使用 32×32 亮度预测单元和陡峭角度内预测模式（上方角度模式 31–34 或下方角度模式 2–5）的帧内编码块，在 MIPS MSA 扩展硬件上解码时即可触发（`bit_depth==8` 且 CPU 支持 MSA 时 MSA 路径被激活）。
- **安全影响**: 读取 `top_array` / `left_array` 结束之后的栈内存（最多 16 字节），这些值被写入解码后的视频帧像素数据，造成栈内存信息泄露（相邻局部变量、潜在的栈金丝雀或保存寄存器值可能被泄露至视频帧中）；同时导致解码输出错误。在极端情况下若 OOB 地址恰好跨页可能引发段错误（DoS），但在典型栈布局下不会崩溃。

<!-- AUDIT_PROMPT_VERSION: 1 -->
