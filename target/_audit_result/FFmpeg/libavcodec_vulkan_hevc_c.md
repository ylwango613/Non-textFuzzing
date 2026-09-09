The HEVC parser allows `num_tile_columns_minus1` up to `sps->ctb_width - 1`, and the Vulkan SDK struct only has 19 slots for `column_width_minus1`. OOB write triggers when `num_tile_columns >= 21` (loop writes index 19 into a 19-element array).

## VULN: Heap Buffer Overflow in set_pps() via Excessive HEVC Tile Columns
- **漏洞类别**: memory-safety
- **函数**: set_pps()
- **行号**: 529-533
- **CWE**: CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted HEVC media file
- **外部触发路径**: ffmpeg -hwaccel vulkan -i crafted.hevc -f null - → avformat_open_input() → ff_hevc_decode_nal_pps() → ff_vk_params_invalidate() → vk_hevc_end_frame() / vk_hevc_create_params() → set_pps()
- **描述**: 在 `set_pps()` 函数（vulkan_hevc.c:529-533）中，向 Vulkan SDK 结构体 `StdVideoH265PictureParameterSet` 的 `column_width_minus1` 数组写入 tile 列宽数据时，未对写入次数做边界检查。Vulkan SDK 将该数组声明为 `column_width_minus1[STD_VIDEO_H265_CHROMA_QP_OFFSET_TILE_COLS_LIST_SIZE]`，即 `column_width_minus1[19]`（仅 19 个元素，有效索引 0-18）。但写循环 `for (int i = 0; i < pps->num_tile_columns - 1; i++)` 在 `num_tile_columns >= 21` 时会向 `column_width_minus1[19]`（越界）及更高索引写入，发生堆缓冲区溢出。该目标结构体 `hdr->pps[idx]` 是通过 `av_mallocz(buf_size)` 分配的 `HEVCHeaderSet` 缓冲区中的一个字段，溢出写入的数据（攻击者控制的 tile 列宽值）将污染缓冲区内相邻的 `HEVCHeaderSPS`、`HEVCHeaderPPS` 等字段乃至堆元数据。HEVC PPS 解析器仅验证 `num_tile_columns_minus1 < sps->ctb_width`（不与 Vulkan SDK 的数组大小做比较），因此攻击者只需构造 `sps->ctb_width >= 21` 的 SPS（如视频宽度 ≥ 336 像素、64 像素 CTB 时 ctb_width ≥ 6，或 16 像素 CTB 时 ctb_width ≥ 22）并在 PPS 中设置 `num_tile_columns_minus1 = 20`（即 21 列），即可稳定触发越界写。同一位置 `row_height_minus1[21]`（21 元素，索引 0-20）在 `num_tile_rows >= 23` 时也存在同样的溢出，对应循环在 vulkan_hevc.c:532-533。
- **触发条件**: 攻击者构造一个畸形 HEVC/H.265 文件：SPS 指定分辨率足够大（CTB 宽度 ≥ 21，例如宽度 ≥ 336px + 16px CTB），PPS 中设置 `tiles_enabled_flag=1` 且 `num_tile_columns_minus1 ≥ 20`（即 ≥ 21 列），使受害者通过支持 Vulkan 视频解码的 FFmpeg 打开该文件。受害系统需要有支持 Vulkan Video Decode H.265 的 GPU，并启用 `-hwaccel vulkan` 选项（或已被配置为默认使用 Vulkan 加速）。
- **安全影响**: 攻击者控制写入越界内存的数据（tile 列宽值，uint16_t），可精确覆盖 `HEVCHeaderSet` 堆分配内的相邻字段，进而破坏解码器内部状态或堆元数据，最坏情况下可实现远程代码执行（RCE）。即使无法直接 RCE，也可造成进程崩溃（DoS）或信息泄露。

## VULN: Heap Buffer Overflow in set_pps() via Excessive HEVC Tile Rows
- **漏洞类别**: memory-safety
- **函数**: set_pps()
- **行号**: 532-533
- **CWE**: CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted HEVC media file
- **外部触发路径**: ffmpeg -hwaccel vulkan -i crafted.hevc -f null - → avformat_open_input() → ff_hevc_decode_nal_pps() → ff_vk_params_invalidate() → vk_hevc_end_frame() / vk_hevc_create_params() → set_pps()
- **描述**: 在 `set_pps()` 函数（vulkan_hevc.c:532-533）中，写循环 `for (int i = 0; i < pps->num_tile_rows - 1; i++) vkpps->row_height_minus1[i] = pps->row_height[i] - 1;` 未对 Vulkan SDK 数组 `row_height_minus1[STD_VIDEO_H265_CHROMA_QP_OFFSET_TILE_ROWS_LIST_SIZE]`（即 `row_height_minus1[21]`，仅 21 个元素）做越界检查。当 HEVC PPS 指定 `num_tile_rows >= 23`（对应 `num_tile_rows_minus1 ≥ 22`）时，循环写入 `row_height_minus1[21]`（越界）及更高索引，发生堆溢出。HEVC 解析器仅限制 `num_tile_rows_minus1 < sps->ctb_height`，未与 Vulkan SDK 的 21 元素上限比较。攻击者通过控制 PPS 中的 `num_tile_rows_minus1` 值及相应的 tile 行高，向越界内存写入攻击者可控的 uint16_t 值。
- **触发条件**: 攻击者构造一个畸形 HEVC/H.265 文件：SPS 指定 CTB 高度 ≥ 23（例如视频高度 ≥ 368px + 16px CTB 时 ctb_height ≥ 23），PPS 中设置 `tiles_enabled_flag=1` 且 `num_tile_rows_minus1 ≥ 22`（即 ≥ 23 行）。受害系统需支持 Vulkan Video 解码且 FFmpeg 启用 Vulkan 加速。
- **安全影响**: 同 tile 列溢出，可覆盖堆缓冲区内相邻结构体字段，最坏情况下可实现 RCE，或导致崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
