I have gathered sufficient context. Here is the complete analysis:

**Group 1 (lines 1–160): `ff_dxva2_hevc_fill_picture_parameters`**

- Lines 145–154: tile column/row arrays are written in a loop bounded only by `pps->num_tile_columns` / `pps->num_tile_rows`, with **no upper-bound check** against the fixed-size arrays `pp->column_width_minus1[]` and `pp->row_height_minus1[]` inside `DXVA_PicParams_HEVC`.
- `nvdec_hevc.c:202–206` explicitly does this check: `if (pps->num_tile_columns > FF_ARRAY_ELEMS(ppc->column_width_minus1))` — confirming the risk is known but absent here.
- The Windows SDK `DXVA_PicParams_HEVC` defines `column_width_minus1[19]` (19 entries) and `row_height_minus1[21]` (21 entries); HEVC allows `num_tile_columns` up to `sps->ctb_width` (e.g., 120 for 1920-pixel wide video with 16×16 CTBs), far exceeding 19.
- OOB write goes into `DXVA_Qmatrix_HEVC qm` (next field in heap-allocated `hevc_dxva2_picture_context`), with attacker-controlled `USHORT` values.

**Group 2 (lines 205–232): `ff_dxva2_hevc_fill_scaling_lists`**

- Indices bounded by iteration constants (16, 64) against `sl->sl[]` array of 64 entries. `pos` values from diagonal scan tables are within [0,63]. No OOB possible.

**Group 3 (lines 234–411): slice/bitstream handling**

- `dxva2_hevc_decode_slice`: Slice count bounded by `MAX_SLICES=256`. `bitstream_size += size` (unsigned wrap) is a minor theoretical DoS, not a memory safety issue given GPU-context bounds.  
- `commit_bitstream_and_slice_buffer`: Buffer end-guard `if (start_code_size + size > end - current)` is correctly present. No OOB.

---

## VULN: OOB Heap Write via Tile Column/Row Array Overflow in DXVA2 HEVC HW Decoder
- **漏洞类别**: memory-safety
- **函数**: ff_dxva2_hevc_fill_picture_parameters()
- **行号**: 149-154
- **CWE**: CWE-787 (Out-of-bounds Write)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted HEVC media file
- **外部触发路径**: ffmpeg -i <crafted.hevc> -hwaccel dxva2 -f null - → avformat_open_input() → hevcdec decode loop → dxva2_hevc_start_frame() → ff_dxva2_hevc_fill_picture_parameters() → OOB write at pp->column_width_minus1[i] / pp->row_height_minus1[i]
- **描述**: `ff_dxva2_hevc_fill_picture_parameters()` copies tile column widths and row heights from the decoded HEVC PPS into the fixed-size Windows SDK `DXVA_PicParams_HEVC` structure without first checking that `pps->num_tile_columns` / `pps->num_tile_rows` are within the array bounds. The DXVA_PicParams_HEVC structure (from dxva.h) defines `USHORT column_width_minus1[19]` (19 entries) and `USHORT row_height_minus1[21]` (21 entries), but the HEVC PPS parser bounds `num_tile_columns` only by `sps->ctb_width` which can be ≫ 19 (e.g., 120 for a 1920-pixel-wide video with 16×16 CTBs). When `num_tile_columns > 19`, the loop `for (i = 0; i < pps->num_tile_columns; i++) pp->column_width_minus1[i] = pps->column_width[i] - 1;` writes attacker-controlled `USHORT` values past the end of the fixed array, overflowing into the adjacent `DXVA_Qmatrix_HEVC qm` field and beyond within the heap-allocated `hevc_dxva2_picture_context`. The same pattern applies to `row_height_minus1[21]` when `num_tile_rows > 21`. Notably, the sibling `nvdec_hevc.c` implementation (line 202) has an explicit `FF_ARRAY_ELEMS` bounds check against this exact risk, confirming awareness of the constraint, while the DXVA2/D3D11VA path does not.
- **触发条件**: 攻击者需构造一个合法的 HEVC 码流，其 PPS 中设置 `tiles_enabled_flag=1`、`uniform_spacing_flag=0`，且 `num_tile_columns_minus1 >= 19`（即 20 个以上 tile 列）或 `num_tile_rows_minus1 >= 21`（即 22 行以上），在使用 DXVA2 或 D3D11VA 硬件加速解码时即可触发。此限制由 SPS 的 `ctb_width` 约束，对于 640×480 以上分辨率（32×32 CTB）均可满足。
- **安全影响**: 攻击者以 USHORT 为粒度对 heap 中相邻对象（`DXVA_Qmatrix_HEVC` 及 `slice_short` 数组）进行受控越界写，在 Windows 平台上使用 DXVA2/D3D11VA 硬件加速的场景下（如 Windows 媒体播放器、基于 FFmpeg 的播放器），可利用此漏洞实现任意代码执行（RCE）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
