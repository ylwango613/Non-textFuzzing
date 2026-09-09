The analysis is complete. The HEVC parser in ps.c validates `num_tile_columns_minus1 < sps->ctb_width` (which can be up to 240 for 16-pixel CTBs), but never caps it at HEVC_MAX_TILE_COLUMNS (20). The VDPAU struct `VdpPictureInfoHEVC::column_width_minus1[20]` and `row_height_minus1[22]` are fixed-size arrays. With no bounds check at lines 162–170 of vdpau_hevc.c, a crafted HEVC stream with tiles_enabled_flag and num_tile_columns > 20 or num_tile_rows > 22 causes a heap buffer overflow. The `chroma_qp_offset_list_len_minus1` issue is not a vulnerability because ps.c validates it is ≤ 5.

## VULN: VDPAU HEVC Tile Array Heap OOB Write via Unchecked num_tile_columns/num_tile_rows
- **漏洞类别**: memory-safety
- **函数**: vdpau_hevc_start_frame()
- **行号**: 162-170
- **CWE**: CWE-787 (Out-of-bounds Write)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted HEVC media file
- **外部触发路径**: ffmpeg -hwaccel vdpau -i <crafted_hevc_file> -f null - -> avcodec_send_packet() -> hevc_decode_frame() -> vdpau_hevc_start_frame() -> heap OOB write at info->column_width_minus1[i] / info->row_height_minus1[i]
- **描述**: In vdpau_hevc_start_frame(), lines 162–164 iterate `pps->num_tile_columns` times and write into the fixed-size array `info->column_width_minus1[]` inside `VdpPictureInfoHEVC`, which the code comments explicitly state "reserves up to the maximum of 20". Similarly, lines 168–170 iterate `pps->num_tile_rows` times into `info->row_height_minus1[]`, which reserves at most 22 entries. However, the HEVC PPS parser in hevc/ps.c (lines 2327–2342) only validates `num_tile_columns_minus1 < sps->ctb_width` and `num_tile_rows_minus1 < sps->ctb_height`, with no cap against HEVC_MAX_TILE_COLUMNS (20) or HEVC_MAX_TILE_ROWS (22). For a crafted video with `log2_ctb_size=4` (16×16 CTB) and width=3840, `sps->ctb_width` = 240, allowing `pps->num_tile_columns` up to 240. Writing 240 attacker-controlled `uint16_t` values starting at `info->column_width_minus1[0]` corrupts up to (240-20)×2 = 440 bytes of heap memory beyond the VdpPictureInfoHEVC struct boundary.
- **触发条件**: Attacker crafts an HEVC bitstream (e.g., .hevc, .mkv, .mp4) with: (1) tiles_enabled_flag=1 in the PPS; (2) num_tile_columns_minus1 > 19 (e.g., 59 for a 3840-wide stream with 64-pixel CTBs); (3) `log2_min_cb_size` and `log2_diff_max_min_coding_block_size` set to yield a small `log2_ctb_size` to maximize `ctb_width`. Victim opens the file using FFmpeg with VDPAU hardware acceleration active (`-hwaccel vdpau`), which requires an NVIDIA GPU with VDPAU support.
- **安全影响**: Heap buffer overflow with attacker-controlled write values (`pps->column_width[i] - 1` are derived from the crafted bitstream) at an attacker-influenced offset beyond the `VdpPictureInfoHEVC` struct. In the worst case this leads to remote code execution through heap exploitation (overwriting function pointers or allocator metadata). Even with mitigations, it reliably causes a crash (denial of service).

<!-- AUDIT_PROMPT_VERSION: 1 -->
