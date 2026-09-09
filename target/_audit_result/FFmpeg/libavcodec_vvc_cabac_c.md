I've completed reading the entire file (2573 lines) in batches and examining the related scan table definitions. The critical issue is now confirmed.

**Key finding:** The scan table `ff_vvc_diag_scan_x[5][5][256]` is a 5×5 array (valid indices 0–4). In `init_residual_coding` at lines 2091–2113, when `log2_zo_tb_width = 0` and `log2_zo_tb_height ≤ 3` (sum ≤ 3), the code sets `log2_sb_w = 1` but never corrects it for this edge case. This causes:
- Line 2112: `ff_vvc_diag_scan_x[0 - 1][...]` → first index = **−1** → OOB read
- Line 2120: `(1 << (0 - 1))` → left shift by −1 → **UB**
- The OOB-read pointer is then used directly as `rc->sb_scan_x_off` / `rc->sb_scan_y_off`, whose contents become `xs`/`ys` loop variables driving subsequent writes into `rc->sb_coded_flag`, `rc->abs_level_pass1`, `rc->abs_level`, `rc->sig_coeff_flag`, and `tb->coeffs`.

VVC ISP (Intra Sub-Partitions) legitimately produces 1×N sub-partition TBs (log2_tb_width = 0), making this reachable from a crafted bitstream.

## VULN: OOB Read/Write via Negative Scan-Table Index in init_residual_coding
- **漏洞类别**: memory-safety
- **函数**: init_residual_coding()
- **行号**: 2091-2121
- **CWE**: CWE-125 (Out-of-bounds Read) / CWE-787 (Out-of-bounds Write)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted VVC media file
- **外部触发路径**: `ffmpeg -i <crafted_vvc_file> -f null -` → `avformat_open_input()` → VVC demux → `avcodec_send_packet()` → `ff_vvc_decode_frame()` → `vvc_decode_slice()` → `ff_vvc_residual_coding()` → `hls_residual_coding()` → `init_residual_coding()` (line 2112)
- **描述**: `init_residual_coding()` derives `log2_sb_w` = 1 whenever `FFMIN(log2_zo_tb_width, log2_zo_tb_height) < 2` (line 2091). When `log2_zo_tb_width = 0` and `log2_zo_tb_height ≤ 3` (sum ≤ 3, so the extended-branch guard at line 2094 is false), `log2_sb_w` stays 1 without correction. At line 2112, `ff_vvc_diag_scan_x[log2_zo_tb_width - log2_sb_w][...] = ff_vvc_diag_scan_x[-1][...]` reads one 5×5-element stride before the table's base address in `.rodata`. The corrupted pointer is stored in `rc->sb_scan_x_off` (and symmetrically `rc->sb_scan_y_off`). These are later dereferenced as arrays of scan-position bytes inside `residual_coding_subblock()` (line 2135 onward): arbitrary byte values from pre-table memory become `xs`/`ys` sub-block coordinates, multiplied and shifted to produce `off = yc * tb->tb_width + xc`, which indexes into the on-stack `rc->abs_level_pass1[MAX_TB_SIZE*MAX_TB_SIZE]` and `rc->sig_coeff_flag` arrays without bounds checking, enabling out-of-bounds write. Additionally, line 2120 evaluates `1 << (log2_zo_tb_width - log2_sb_w) = 1 << -1`, which is undefined behavior in C.
- **触发条件**: 攻击者构造包含 VVC ISP（帧内子分区）模式的 .vvc/.mp4 文件，使解码器产生宽度为 1 像素（`log2_tb_width = 0`）且高度 ≤ 8 像素（`log2_tb_height ≤ 3`）的非跳变（non-TS）变换块（TransformBlock），且该块携带残差编码数据（`tu_y_coded_flag = 1`）。
- **安全影响**: 最坏情况：栈上 `ResidualCoding` 结构内多个数组（`abs_level_pass1[4096]`、`sig_coeff_flag[4096]` 等）发生越界写入，可能导致栈帧破坏，进而实现远程代码执行（RCE）；最低限度导致进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
