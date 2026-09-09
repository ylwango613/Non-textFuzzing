I've completed a thorough analysis. Here is the summary of findings:

**Batch 1 (lines 0-600):** Encoder context setup, SEI metadata, slice and reference list setup. The `setup_refs()` function at line 414 allocates `rps_poc[MAX_DPB_SIZE]` and `rps_used[MAX_DPB_SIZE]` (16 each), then potentially writes more than 16 entries when L0/L1 share references — but this is bounded by `MAX_PICTURE_REFERENCES = 2`, limiting the excess to at most +2.

**Batch 2 (lines 600-1200):** Profile init, encoder options, sequence header init, SPS/VPS/PPS conversion. **Key finding at lines 1110–1114:** CBS permits `num_tile_columns_minus1` up to `HEVC_MAX_TILE_COLUMNS = 20`, but the Vulkan `StdVideoH265PictureParameterSet::column_width_minus1` array has only `STD_VIDEO_H265_CHROMA_QP_OFFSET_TILE_COLS_LIST_SIZE = 19` elements. Similarly CBS permits `num_tile_rows_minus1` up to `HEVC_MAX_TILE_ROWS = 22`, but the Vulkan `row_height_minus1` array has only `STD_VIDEO_H265_CHROMA_QP_OFFSET_TILE_ROWS_LIST_SIZE = 21` elements.

**Batch 3 (lines 1200-1380):** `create_session_params()` (where `VulkanH265Units vk_units = {0}` is on the stack and is the overflow target), `init_base_units()` with GPU driver feedback path (parses CBS-valid PPS with 20+ tile columns and stores it), and `parse_feedback_units()`.

**Batch 4 (lines 1380-1820):** Write helpers and codec registration — no additional memory safety issues found.

## VULN: OOB Write in base_unit_to_vk() via Tile Column/Row Array Size Mismatch
- **漏洞类别**: memory-safety
- **函数**: base_unit_to_vk()
- **行号**: 1110-1114
- **CWE**: CWE-787 (Out-of-bounds Write)
- **CVSS v3.1**: 5.0 (AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L)
- **严重程度**: Medium
- **攻击向量**: crafted Vulkan driver feedback or encoder configured with ≥21 tile columns / ≥23 tile rows
- **外部触发路径**: ffmpeg -i <file> -c:v hevc_vulkan -tiles 21x1 output.h265 -> vulkan_encode_h265_init() -> init_base_units() -> [GetEncodedVideoSessionParametersKHR feedback with 20+ tile columns parsed by parse_feedback_units()] -> create_session_params() -> base_unit_to_vk() -> OOB write into stack-allocated VulkanH265Units.pps
- **描述**: In `base_unit_to_vk()`, two loops copy tile column and row widths from the CBS-parsed `H265RawPPS` struct into the Vulkan `StdVideoH265PictureParameterSet` struct. The CBS parser permits `num_tile_columns_minus1` up to `HEVC_MAX_TILE_COLUMNS = 20` (stored in `H265RawPPS.column_width_minus1[20]`), and `num_tile_rows_minus1` up to `HEVC_MAX_TILE_ROWS = 22` (stored in `H265RawPPS.row_height_minus1[22]`). However, the destination Vulkan struct (version `VK_STD_VULKAN_VIDEO_CODEC_H265_ENCODE_SPEC_VERSION`) only defines `column_width_minus1[STD_VIDEO_H265_CHROMA_QP_OFFSET_TILE_COLS_LIST_SIZE = 19]` and `row_height_minus1[STD_VIDEO_H265_CHROMA_QP_OFFSET_TILE_ROWS_LIST_SIZE = 21]`. The loops `for (int i = 0; i < pps->num_tile_columns_minus1; i++)` and `for (int i = 0; i < pps->num_tile_rows_minus1; i++)` have no upper bound against the destination array size, so when `num_tile_columns_minus1 == 20` the write at index 19 overflows into `row_height_minus1[0]`, and when `num_tile_rows_minus1 == 22` the write at index 21 overflows into the next field of the Vulkan PPS struct. The victim buffer `VulkanH265Units vk_units = { 0 }` is a stack-allocated local variable in `create_session_params()`, so adjacent struct fields — including `pps_scaling`, `vps`, `ptl_vps`, and `dpbm_vps` — are corrupted on the stack.
- **触发条件**: (1) H.265 Vulkan encoder is invoked with 21 or more tile columns (e.g., `ffmpeg ... -c:v hevc_vulkan -tiles 21x1 ...`) so that `ff_hw_base_encode_init_params_h265()` sets `num_tile_columns_minus1 = 20`; OR (2) A Vulkan driver returns encoder-feedback SPS/PPS bitstream (via `GetEncodedVideoSessionParametersKHR`) in which CBS parses a PPS with `num_tile_columns_minus1 = 20` or `num_tile_rows_minus1 = 22`, and the encoder stores it via `parse_feedback_units()` before the next `create_session_params()` call.
- **安全影响**: Stack buffer overflow corrupts adjacent fields of the locally-allocated `VulkanH265Units` struct, leading to incorrect Vulkan API calls that may cause driver-side memory corruption, process crash (DoS), or — under a controlled-overlap memory layout — potential code execution. The overflow is 1–2 `uint16_t` elements (2–4 bytes) past the respective arrays.

<!-- AUDIT_PROMPT_VERSION: 1 -->
