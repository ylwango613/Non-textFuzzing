分析完成。对 `mlpdsp.c` 的所有函数及调用链已进行深入审计：

**mlp_filter_channel**（L27-58）：
- `firbuf/iirbuf` 的访问依赖 `state_buffer[NUM_FILTERS][MAX_BLOCKSIZE + MAX_FIR_ORDER]`，边界在 `filter_channel` 中严格对齐
- `firorder ≤ MAX_FIR_ORDER=8`，`iirorder ≤ MAX_IIR_ORDER=4`，在 `read_filter_params` 中校验
- `blocksize ≤ MAX_BLOCKSIZE=160`，在 `read_decoding_params` 中校验
- `sample_buffer += MAX_CHANNELS` 步进访问正确

**ff_mlp_rematrix_channel**（L60-90）：
- `samples[dest_ch]`：`dest_ch = s->matrix_out_ch[mat] ≤ s->max_matrix_channel ≤ MAX_MATRIX_CHANNEL_TRUEHD=7 < MAX_CHANNELS=8` ✓
- `noise_buffer[index]`：`index &= access_unit_size_pow2 - 1` 在读取前掩码，`access_unit_size_pow2 ≤ MAX_BLOCKSIZE_POW2=256 = sizeof(noise_buffer)` ✓
- `coeffs[src_ch]`：`matrix_coeff[mat][MAX_CHANNELS]`，maxchan 通过 noise_type 限制满足 < 8 ✓

**ff_mlp_pack_output**（L100-126）：
- `mat_ch = ch_assign[out_ch]`，`ch_assign` 在 `read_restart_header` 中验证 `ch_assign ≤ max_matrix_channel ≤ 7 < 8` ✓
- `sample_buffer[i][mat_ch]`，第二维 mat_ch < MAX_CHANNELS ✓

**generate_2_noise_channels** 的 `sample_buffer[i][maxchan+2]`：
- 当 `noise_type=0` 时，`read_restart_header` 中有明确检查：`max_matrix_channel > MAX_MATRIX_CHANNEL_MLP(=5) && !noise_type → PATCHWELCOME`，故 maxchan+2 ≤ 7 < 8 ✓

所有参数经上游充分校验，无可外部触发的内存安全漏洞。

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
