Analysis complete. The full file has been read in three batches (lines 0-600, 600-1200, 1200-1309). Let me now confirm the struct layout of the key vulnerability path.

**Batch 1 findings (lines 0-600):** Pool allocation in `qsv_decode_init_context` uses `av_image_get_buffer_size` which calls `av_image_check_size` — overflow is caught. The `qsv_get_continuous_buffer` linestride calculations match pool sizes correctly for all pixel formats. No memory safety issue here.

**Batch 2 findings (lines 600-1200):** `qsv_export_film_grain` (lines 628-691) copies film-grain point arrays from `mfxExtAV1FilmGrainParam` into `AVFilmGrainAOMParams` using `NumYPoints`/`NumCbPoints`/`NumCrPoints` from the Intel MFX SDK as loop bounds — **with no bounds check** against the hard-coded array sizes `y_points[14]`, `uv_points[0][10]`, `uv_points[1][10]`. The AV1 `num_y_points` field is 4-bit in the bitstream (values 0-15 encodable; AV1 spec cap is 14), meaning a non-conforming bitstream can set it to 15. If the Intel MFX SDK passes this value through unclamped, FFmpeg writes past the end of the heap-allocated `AVFilmGrainParams` struct.

**Batch 3 findings (lines 1200-1309):** Codec registration, option tables — no memory safety issues.

**Crop underflow** at lines 951-952 (`Width - (CropX + CropW)` assigned to `size_t`) is a correctness concern but `av_frame_apply_cropping` validates non-positive dimensions, limiting direct memory impact.

## VULN: qsv_export_film_grain OOB Write via Unchecked Film Grain Point Count
- **漏洞类别**: memory-safety
- **函数**: qsv_export_film_grain()
- **行号**: 654-672
- **CWE**: CWE-787 (Out-of-bounds Write)
- **CVSS v3.1**: 7.5 (AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted AV1 media file
- **外部触发路径**: ffmpeg -export_side_data +film_grain -i crafted.av1 -f null - → qsv_decode_frame() → qsv_process_data() → qsv_decode() [line 901: film_grain branch] → qsv_export_film_grain() [line 654-672: unchecked loop bounds OOB write]
- **描述**: 在 `qsv_export_film_grain()`（qsvdec.c:654-672）中，函数将 Intel MFX SDK 解析 AV1 码流返回的 `mfxExtAV1FilmGrainParam::NumYPoints`（`mfxU16`，最大 65535）、`NumCbPoints`、`NumCrPoints` 直接赋给 `aom->num_y_points`/`num_uv_points[]` 并作为循环上界，但 **未做任何边界检查**。目标数组 `AVFilmGrainAOMParams::y_points[14][2]` 仅有 14 个条目，`uv_points[2][10][2]` 每通道仅 10 个条目。AV1 规范将 `num_y_points` 编码为 4-bit 字段（值域 0-15），其中值 15 可被编码进非合规码流；如果 MFX SDK 未将该值限制到规范上界 14，FFmpeg 的循环将越界写入堆分配的 `AVFilmGrainParams` 结构体（由 `av_film_grain_params_create_side_data()` 分配），破坏 `chroma_scaling_from_luma`、`num_uv_points`、`uv_points` 等紧邻字段及堆元数据。
- **触发条件**: 攻击者构造一个 AV1 视频文件，在 film_grain_params() OBU 中将 `num_y_points`（4-bit）设为 15（非合规但码流合法），或将 `num_cb_points`/`num_cr_points` 设为 11-15；使用者通过 Intel QSV（oneVPL ≥ 1.34）解码该文件并启用 `AV_CODEC_EXPORT_DATA_FILM_GRAIN`（例如 `ffmpeg -export_side_data +film_grain -c:v av1_qsv`）。需要 MFX SDK 将超规范值透传给 FFmpeg（而非夹紧或报错）。
- **安全影响**: 最坏情况下：攻击者控制写入越界区域的字节值（来自 `PointY[i].Value/Scaling`），可精准覆盖 `AVFilmGrainParams` 堆块之外的内存，结合堆风水可实现远程代码执行（RCE）；退而求其次可导致进程崩溃（DoS）或信息泄露（读取 `ext_param->PointY[14+]`，越界读取 `QSVFrame::av1_film_grain_param` 结构体相邻字段）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
