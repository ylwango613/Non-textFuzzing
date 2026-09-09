I've completed my full analysis of `vaapi_av1.c`. Here is the consolidated audit result:

## VULN: OOB Write in vaapi_av1_start_frame via tile_cols/tile_rows=64 off-by-one
- **漏洞类别**: memory-safety
- **函数**: vaapi_av1_start_frame()
- **行号**: 302-309
- **CWE**: CWE-787 (Out-of-bounds Write)
- **CVSS v3.1**: 6.3 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted AV1 media file
- **外部触发路径**: ffmpeg -hwaccel vaapi -i crafted.av1 -f null - → avcodec_send_packet() → av1_decode_frame() → vaapi_av1_start_frame() → OOB write at `pic_param.width_in_sbs_minus_1[63]` / `pic_param.height_in_sbs_minus_1[63]`
- **描述**: 在 `vaapi_av1_start_frame()` 中，代码用两个循环将 `frame_header->width_in_sbs_minus_1[i]` 和 `frame_header->height_in_sbs_minus_1[i]` 分别写入栈上本地变量 `VADecPictureParameterBufferAV1 pic_param` 的 `pic_param.width_in_sbs_minus_1[i]` 和 `pic_param.height_in_sbs_minus_1[i]` 字段。问题在于：AV1 规格允许最多 `AV1_MAX_TILE_COLS = AV1_MAX_TILE_ROWS = 64` 个分块列/行（CBS 解析器在 uniform 模式下当 `sb_cols=64` 时可产生 `tile_cols=64`，在 non-uniform 模式下循环条件 `i < AV1_MAX_TILE_COLS=64` 最多令 `tile_cols=64`），但 VA API 结构体 `VADecPictureParameterBufferAV1` 中的对应数组只有 63 个元素（`uint16_t width_in_sbs_minus_1[63]`，`uint16_t height_in_sbs_minus_1[63]`，有效下标 0–62）。当 `tile_cols == 64` 时，循环写入 `pic_param.width_in_sbs_minus_1[63]`（下标越界 1），实际写入紧邻的 `pic_param.height_in_sbs_minus_1[0]`（可被后续第二个循环覆盖）。当 `tile_rows == 64` 时，循环写入 `pic_param.height_in_sbs_minus_1[63]`（同样越界），实际写入紧邻的 `pic_param.tile_count_minus_1` 字段，该字段在此后**不会**被任何代码重新赋值，带有攻击者控制的值（`frame_header->height_in_sbs_minus_1[63]`，uint8_t，范围 0–255，零扩展为 uint16_t）被直接传入 `ff_vaapi_decode_make_param_buffer()` 并提交给 VA API 驱动。
- **触发条件**: 攻击者构造合法 AV1 bitstream（OBU 帧）：使用 uniform tile spacing，`tile_cols = 64`（例如 `tile_cols_log2 = 6`，帧宽包含 64 个 superblock），且/或 `tile_rows = 64`。这在 AV1 规格范围内完全合法，CBS 解析器不会拒绝。
- **安全影响**: 攻击者对 `VADecPictureParameterBufferAV1.tile_count_minus_1` 字段写入可控 1 字节值（0–255）。该结构体随即提交给 VAAPI 内核驱动（iHD、Mesa VA-API 等）。若驱动在 large-scale tile 路径中使用 `tile_count_minus_1` 进行数组下标或内存分配，可能触发驱动层越界访问，最坏情况下导致内核崩溃（DoS）或驱动进程内存破坏（潜在的权限提升）。即使驱动忽略该字段，这仍是一个可远程触发的、攻击者完全控制写入值的栈结构体内 OOB Write，符合 CWE-787 的认定标准。

<!-- AUDIT_PROMPT_VERSION: 1 -->
