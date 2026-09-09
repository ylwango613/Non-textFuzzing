Based on my thorough analysis of `vdpau_av1.c`, all related headers, and the CBS parsing code, let me document my findings.

**Analysis Group 1 (lines 43-273, `vdpau_av1_start_frame`):**
- `lr_type` array indexing (lines 161-163): CBS uses `fbs(2, lr_type[i])` → constrained 0-3. `remap_lr_type[4]` has 4 elements. **SAFE.**
- `ref_frame_idx` as array index (lines 228-247): CBS uses `fbs(3, ...)` → constrained 0-7. In short-signaling path, fallback loop always finds valid ref ≥ 0. **SAFE.**
- `cdef_bits` loop (lines 201-204): CBS uses `fb(2, cdef_bits)` → 0-3, so `1<<cdef_bits` ≤ 8. Source arrays are exactly 8 elements. **SAFE IF target arrays sized ≥ 8.**
- Film grain loops (lines 251-267): Fixed iterations match source array sizes exactly (14, 10, 24, 25). **SAFE.**
- `tile_widths[i]`/`tile_heights[i]` (lines 193-198): CBS constrains `tile_cols`/`tile_rows` ≤ 64 via `FFMIN(sb_cols, AV1_MAX_TILE_COLS)`. **SAFE IF VdpPictureInfoAV1 arrays ≥ 64.**

**Analysis Group 2 (lines 275-318, `vdpau_av1_decode_slice`):**
- Line 287: `nb_slices = frame_header->tile_cols * frame_header->tile_rows`. Both are `uint16_t`, CBS allows up to 64 each → `nb_slices` up to 4096.
- Lines 291-292, 308-309: `info->tile_info[i*2]` and `info->tile_info[i*2 + 1]` written with no upper bounds check on `nb_slices` or `tile_num`.
- The `VdpPictureInfoAV1.tile_info` field is defined in the system `vdpau/vdpau.h` as `uint32_t tile_info[256]` (128 tiles × 2 entries), per the VDPAU AV1 specification. AV1 allows up to 4096 tiles (64×64). **NO bounds check before writing → OOB heap write.**

## VULN: tile_info Heap OOB Write via Unchecked Tile Count in vdpau_av1_decode_slice
- **漏洞类别**: memory-safety
- **函数**: vdpau_av1_decode_slice()
- **行号**: 287-310
- **CWE**: CWE-787 (Out-of-bounds Write)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted AV1 media file
- **外部触发路径**: `ffmpeg -i <crafted.av1> -vcodec copy -o /dev/null` → `avformat_open_input()` → AV1 demuxer → `avcodec_send_packet()` → `av1_decode_frame()` → `vdpau_av1_decode_slice()` → `info->tile_info[tile_num*2]` OOB write
- **描述**: In `vdpau_av1_decode_slice()`, `nb_slices` is computed as `frame_header->tile_cols * frame_header->tile_rows` (both `uint16_t`, max 64 each per AV1 spec, giving up to 4096 tiles). The function then writes `info->tile_info[i*2]` and `info->tile_info[i*2 + 1]` for every tile without checking whether the index exceeds the array capacity. `VdpPictureInfoAV1.tile_info` is declared as `uint32_t tile_info[256]` in the system VDPAU header, accommodating only 128 tiles (2 uint32 entries per tile). An AV1 stream with more than 128 tiles (e.g., tile_cols=13 × tile_rows=10 = 130 tiles) causes the loop to write past the end of `tile_info`, corrupting adjacent fields in the `vdpau_picture_context` structure (which is a heap allocation of size `sizeof(struct vdpau_picture_context)`). This is a controlled, attacker-driven heap out-of-bounds write.
- **触发条件**: 攻击者需构造一个合法的 AV1 码流，其中 `tile_cols × tile_rows > 128`（例如 `tile_cols=13, tile_rows=10` 即 130 块），并通过 VDPAU 硬件解码路径（`-hwaccel vdpau`）进行解码。CBS 解析器允许最多 64×64=4096 个 tile，不会拒绝该码流。
- **安全影响**: 堆越界写入（heap OOB write），可覆盖 `vdpau_picture_context` 后续字段或堆元数据，结合 heap feng-shui 可能导致远程代码执行（RCE）；最坏情况下攻击者可控覆盖内容，实现任意代码执行或进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
