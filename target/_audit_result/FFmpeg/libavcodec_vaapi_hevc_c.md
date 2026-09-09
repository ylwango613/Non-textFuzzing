The analysis is complete. The PPS parser only bounds `num_tile_columns_minus1 < sps->ctb_width` (not `< HEVC_MAX_TILE_COLUMNS = 20`) and `num_tile_rows_minus1 < sps->ctb_height` (not `< HEVC_MAX_TILE_ROWS = 22`), but the VA-API structs only allocate `column_width_minus1[19]` and `row_height_minus1[21]`. Any HD+ resolution stream (ctb_width ≥ 20) can trigger the OOB writes.

## VULN: VAAPI HEVC tile column-width OOB heap write
- **漏洞类别**: memory-safety
- **函数**: vaapi_hevc_start_frame()
- **行号**: 220-221
- **CWE**: CWE-787 (Out-of-bounds Write)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted HEVC media file with tiles_enabled_flag=1 and large num_tile_columns_minus1
- **外部触发路径**: ffmpeg -hwaccel vaapi -i malicious.hevc -f null - → avformat_open_input() → avcodec_open2() → ff_hevc_vaapi_hwaccel.start_frame() → vaapi_hevc_start_frame()
- **描述**: 在 `vaapi_hevc_start_frame()` 中，代码使用 `pps->num_tile_columns` 作为上界对 `pic_param->column_width_minus1[]` 进行写循环（第220-221行）。但 VA-API 结构体 `VAPictureParameterBufferHEVC` 中该数组仅声明了 19 个元素（`uint16_t column_width_minus1[19]`，索引 0-18）。HEVC PPS 解析器（ps.c 第2327-2328行）只验证 `num_tile_columns_minus1 < sps->ctb_width`，而不检查 `< HEVC_MAX_TILE_COLUMNS(=20)`。因此对任何 ctb_width ≥ 20 的流（1280×任意分辨率，使用 64×64 CTB 即可触发），攻击者可将 `num_tile_columns_minus1` 设为 19（num_tile_columns=20），导致循环写入 `column_width_minus1[19]`，越界一个 `uint16_t`，覆盖 VA-API 结构中紧随其后的 `row_height_minus1[0]`。若 `num_tile_columns` 远大于 19（如 ctb_width=200），则产生大规模堆越界写入，可覆盖 `VAPictureParameterBufferHEVCExtension` 中后续字段乃至 `VAAPIDecodePictureHEVC` 的 `last_slice_param`、`last_buffer`（指针）和 `last_size`（size_t），形成可控写入原语。
- **触发条件**: 攻击者需构造 tiles_enabled_flag=1、uniform_spacing_flag=0、num_tile_columns_minus1≥19（最小触发）的 HEVC 码流，同时 SPS 的 ctb_width ≥ 20（分辨率 ≥ 1280 像素宽，CTB 64×64）。受害者需以 `-hwaccel vaapi` 选项解码该流（VAAPI 加速路径）。
- **安全影响**: 堆越界写入 VAAPIDecodePictureHEVC 分配的 heap chunk；写入内容为攻击者可控的 uint16_t 值（tile 列宽度）。在足够大的 num_tile_columns 下，可覆盖 last_buffer 指针与 last_size，使 vaapi_hevc_end_frame 中 ff_vaapi_decode_make_slice_buffer 使用攻击者控制的指针/长度执行内存操作，最坏情况下导致远程代码执行（RCE）；最低影响为崩溃（DoS）。

## VULN: VAAPI HEVC tile row-height OOB heap write
- **漏洞类别**: memory-safety
- **函数**: vaapi_hevc_start_frame()
- **行号**: 223-224
- **CWE**: CWE-787 (Out-of-bounds Write)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted HEVC media file with tiles_enabled_flag=1 and large num_tile_rows_minus1
- **外部触发路径**: ffmpeg -hwaccel vaapi -i malicious.hevc -f null - → avformat_open_input() → avcodec_open2() → ff_hevc_vaapi_hwaccel.start_frame() → vaapi_hevc_start_frame()
- **描述**: 与列宽越界问题对称：代码以 `pps->num_tile_rows` 为上界写 `pic_param->row_height_minus1[]`（第223-224行），但 VA-API 结构中该数组仅有 21 个元素（`uint16_t row_height_minus1[21]`，索引 0-20）。HEVC PPS 解析器（ps.c 第2334-2335行）只验证 `num_tile_rows_minus1 < sps->ctb_height`，未检查 `< HEVC_MAX_TILE_ROWS(=22)`。当 ctb_height ≥ 22（720像素高，CTB 32×32 即可），攻击者将 `num_tile_rows_minus1` 设为 21（num_tile_rows=22），循环写入 `row_height_minus1[21]`，越界一个 `uint16_t`，命中紧随其后的 `slice_parsing_fields` 联合体（uint32_t）低2字节，破坏 VA-API slice 解析标志位，可触发 VA-API 驱动内部的错误处理或进一步内存损坏。若 ctb_height 更大（如视频高度1080，32×32 CTB → ctb_height=34），则 num_tile_rows 可高达 34，产生大规模越界写入，同样可覆盖 last_buffer 指针和 last_size。
- **触发条件**: 攻击者构造 tiles_enabled_flag=1、uniform_spacing_flag=0、num_tile_rows_minus1≥21 的 HEVC 码流，SPS ctb_height ≥ 22（分辨率 ≥ 704 像素高，CTB 32×32）。受害者需以 `-hwaccel vaapi` 选项解码该流。
- **安全影响**: 堆越界写入，破坏 VAPictureParameterBufferHEVC 内的 slice_parsing_fields 及其后续字段，进而可能覆盖 VAAPIDecodePictureHEVC 的 last_buffer（指针）、last_size；最坏情况下被利用实现任意地址写，导致 RCE；至少造成崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
