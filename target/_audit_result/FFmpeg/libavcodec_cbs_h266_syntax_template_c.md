I have completed my audit. The file contains a confirmed heap buffer overflow in the VPS (Video Parameter Set) parsing code.

**Key finding:** When `ols_mode_idc == 2` and `vps_num_output_layer_sets_minus2 = 255`, `total_num_olss` becomes 257. The constraint at line 788 permits `vps_num_ptls_minus1 = 256`. Two separate loops (lines 794–803 and 933–938) then iterate with `i` reaching 256, writing out-of-bounds into three fixed-size arrays — `vps_pt_present_flag[VVC_MAX_PTLS]`, `vps_ptl_max_tid[VVC_MAX_PTLS]`, and `vps_profile_tier_level[VVC_MAX_PTLS]` — all of size 256, causing heap corruption.

## VULN: OOB Heap Write in VPS Parsing via vps_num_ptls_minus1 Exceeding VVC_MAX_PTLS
- **漏洞类别**: memory-safety
- **函数**: FUNC(vps)() (cbs_h266_read_vps / cbs_h266_write_vps)
- **行号**: 788-803 和 933-938
- **CWE**: CWE-787 (Out-of-bounds Write)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted VVC/H.266 media file
- **外部触发路径**: ffmpeg -i <crafted_vvc_file> -f null - → avformat_open_input() → ff_read_packet() → CBS VVC demux/decode → cbs_h266_read_unit() → cbs_h266_read_vps() → FUNC(vps)() → OOB write at vps_profile_tier_level[256]
- **描述**: 在 `FUNC(vps)()` 中，`total_num_olss` 由 `vps_num_output_layer_sets_minus2 + 2` 计算（后者 8 位可控，范围 0-255，故 `total_num_olss` 最大 257）。第 788 行 `u(8, vps_num_ptls_minus1, 0, total_num_olss - 1)` 因此允许 `vps_num_ptls_minus1 = 256`。第 794-803 行的循环以及第 933-938 行的循环均执行 `for (i = 0; i <= current->vps_num_ptls_minus1; i++)`，在 `i = 256` 时分别写入 `current->vps_pt_present_flag[256]`、`current->vps_ptl_max_tid[256]` 以及调用 `profile_tier_level(... vps_profile_tier_level + 256 ...)`。三个数组均声明为 `[VVC_MAX_PTLS]`（大小 256，合法索引 0-255），导致堆溢出写。`sizeof(H266RawProfileTierLevel) ≈ 1376 字节`，最坏情况下越界写入 1376 字节，破坏紧随其后的 `vps_ols_ptl_idx`、`vps_dpb_params` 等关键结构体字段。
- **触发条件**: 攻击者构造包含如下特征的 VPS NAL 单元的 VVC（H.266）裸流或封装于 MP4/MKV 容器中的文件：`vps_max_layers_minus1 > 0`、`vps_each_layer_is_an_ols_flag = 0`、`vps_ols_mode_idc = 2`、`vps_num_output_layer_sets_minus2 = 255`（使 `total_num_olss = 257`），并将 `vps_num_ptls_minus1` 设为 256（在 bitstream 中合法编码为 8 位值 0x100）。
- **安全影响**: 堆内存越界写入，破坏 `H266RawVPS` 结构体内后续字段，进而在后续 SPS/PPS/Slice 解析时触发进一步的内存破坏，最坏情况下可导致远程代码执行（RCE）；最低影响为进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
