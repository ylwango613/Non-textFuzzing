I have read the entire file (739 lines) and cross-referenced all key structures. Let me now finalize the analysis with a clear summary of the findings.

**Key findings:**

1. In both `pred_spatial_direct_motion()` (lines 302–305) and `pred_temp_direct_motion()` (lines 521–524), when `col_fieldoff = -1` (BOTTOM FIELD current picture with TOP FIELD as L1 reference) and `mb_y = 0` (first macroblock row), the adjustment `mb_xy += h->mb_stride * sl->col_fieldoff` makes `mb_xy` negative (e.g., `-h->mb_stride`).

2. The negative `mb_xy` is then immediately used at lines 354–357 / 579–582:
   - `h->mb2b_xy[mb_xy]` → OOB read of `mb2b_xy` array (uint32_t, negative index)
   - `parent->motion_val[0][h->mb2b_xy[mb_xy]]` → large OOB read using garbage index
   - `parent->ref_index[0][4 * mb_xy]` → OOB read 4×mb_stride bytes before the ref_index buffer

3. The OOB-read `l1ref0` value (int8_t from heap noise) is subsequently used as an unchecked index into `map_col_to_list0[0][ref0 + ref_offset]` (array size 48), enabling a secondary OOB read.

4. No bounds check anywhere between the `col_fieldoff` adjustment and the array indexing. Confirmed no guard for negative `mb_y` / `mb_xy`.

5. No OOB **write** is observed; all issues are OOB reads (CWE-125), enabling heap info leak + crash.

## VULN: OOB Read via Negative mb_xy in H.264 Field-Picture B-Slice Direct Motion
- **漏洞类别**: memory-safety
- **函数**: pred_spatial_direct_motion() / pred_temp_direct_motion()
- **行号**: 302-305 / 354-357 (pred_spatial_direct_motion); 521-524 / 579-582 (pred_temp_direct_motion)
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.1 (AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted media file (H.264 bitstream with field-coded B-slices)
- **外部触发路径**: ffmpeg -i crafted.h264 -f null - -> avformat_open_input() -> avcodec_send_packet() -> ff_h264_execute_decode_slices() -> decode_slice() -> ff_h264_decode_mb_cavlc()/ff_h264_decode_mb_cabac() -> ff_h264_pred_direct_motion() -> pred_spatial_direct_motion() / pred_temp_direct_motion()
- **描述**: 在 `pred_spatial_direct_motion()` 和 `pred_temp_direct_motion()` 中，当当前图像是 BOTTOM FIELD、L1 参考帧是 TOP FIELD（field_picture=1）时，`ff_h264_direct_ref_list_init()` 将 `col_fieldoff` 设为 -1。此后在解码第一行宏块（`sl->mb_y == 0`）时，代码执行 `mb_y += sl->col_fieldoff`（=-1）和 `mb_xy += h->mb_stride * sl->col_fieldoff`，使 `mb_xy` 变为负值（如 `-h->mb_stride`）。随后代码无任何边界检查，直接以此负值 `mb_xy` 索引：①`h->mb2b_xy[mb_xy]`（`uint32_t` 数组越界读，取得垃圾值作下标）；②`parent->motion_val[0][garbage_index]`（motion_val 数组大幅越界读）；③`parent->ref_index[0][4 * mb_xy]`（在 ref_index 缓冲区起始前 `4*|mb_xy|` 字节处越界读）。读取的 int8_t 垃圾值进一步用作 `map_col_to_list0[0][ref0 + ref_offset]` 的下标（数组仅 48 元素），引发二次越界读。
- **触发条件**: 构造 H.264 码流，包含：1）成对 field picture：先一个 TOP FIELD 参考帧（field_picture=1），再一个将其作为 L1 引用的 BOTTOM FIELD B-slice；2）该 B-slice 的首个宏块（mb_y=0）使用 direct mode（IS_DIRECT）且被标记为 interlaced（MB_TYPE_INTERLACED，在 field picture 中自动设置）；3）L1 参考不是 MBAFF 帧（`!parent->mbaff`），保证 `col_fieldoff = -1`。
- **安全影响**: 堆内存越界读导致进程崩溃（SIGSEGV，高可靠性 DoS）；motion_val/ref_index/mb2b_xy 所在堆区域的内容通过 `mv_col` 运算泄漏到 `sl->mv_cache`，可被利用实现堆地址/指针信息泄露（ASLR 绕过），进而为后续 RCE 提供基础。

<!-- AUDIT_PROMPT_VERSION: 1 -->
