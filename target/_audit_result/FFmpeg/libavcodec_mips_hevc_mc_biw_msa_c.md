I now have a complete picture of all the hardcoded loop-count vulnerabilities. Let me write the final report with the confirmed bugs.

## VULN: hevc_biwgt_copy_48w_msa ignores height, hardcodes 64 rows — OOB read/write
- **漏洞类别**: memory-safety
- **函数**: hevc_biwgt_copy_48w_msa()
- **行号**: 567-616 (关键语句: 595)
- **CWE**: CWE-125 / CWE-787 (Out-of-bounds Read / Out-of-bounds Write)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted HEVC media file
- **外部触发路径**: ffmpeg -i crafted.hevc -f null - -> avformat_open_input() -> avcodec_open2() -> ff_hevc_dsp_init_mips() [registers ff_hevc_put_hevc_bi_w_pel_pixels48_8_msa → hevc_biwgt_copy_48w_msa] -> hevcdec.c:hls_prediction_unit() -> mc_bi_w() -> put_hevc_qpel_bi_w[8][0][0](..., block_h, ...) -> hevc_biwgt_copy_48w_msa()
- **描述**: 在 `hevc_biwgt_copy_48w_msa` 函数中，主循环使用硬编码计数 `for (loop_cnt = 64; loop_cnt--;)`（第595行），强制读写恰好64行，完全忽略传入的 `height` 参数。该函数经由 `hevcdsp_init_mips.c:405` 注册为 `c->put_hevc_qpel_bi_w[8][0][0]`，对应宽度=48的无滤波bi-weighted预测。HEVC标准允许宽48像素的AMP块（来自64像素宽CTB的非对称分割）配合高度16或32（例如从64×32的CTB分割得到48×32+16×32块）。当 `height=32` 时，函数读取src0_ptr的64行而非32行，同时向dst写入64行而非32行，造成32行×48字节=1536字节的堆越界读和堆越界写。src1_ptr（lc->tmp，大小为MAX_PB_SIZE²=64×64 int16_t）本身足够大不会溢出，但帧缓冲区src0（参考帧）和dst（解码帧）的OOB访问真实存在。
- **触发条件**: 构造HEVC码流，启用双向加权预测（slice_type=B且weighted_bipred_flag=1），设置motion partition为AMP模式使宽=48像素、高=32或16像素（例如64×32 CU的非对称分割），同时确保码流在MIPS MSA目标上解码（MSA优化路径）。
- **安全影响**: 堆OOB写可覆盖相邻帧缓冲区或堆元数据，在精心控制的堆布局下可导致任意代码执行（RCE）；堆OOB读可泄露进程内存（信息泄露）；最差情况导致崩溃（DoS）。

## VULN: hevc_hz_biwgt_8t_48w_msa ignores height, hardcodes 64 rows — OOB read/write
- **漏洞类别**: memory-safety
- **函数**: hevc_hz_biwgt_8t_48w_msa()
- **行号**: 1205-1306 (关键语句: 1253)
- **CWE**: CWE-125 / CWE-787 (Out-of-bounds Read / Out-of-bounds Write)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted HEVC media file
- **外部触发路径**: ffmpeg -i crafted.hevc -f null - -> avformat_open_input() -> ff_hevc_dsp_init_mips() [注册 ff_hevc_put_hevc_bi_w_qpel_h48_8_msa → hevc_hz_biwgt_8t_48w_msa] -> hevcdec.c:mc_bi_w() -> put_hevc_qpel_bi_w[8][0][1](..., block_h, ...) -> hevc_hz_biwgt_8t_48w_msa()
- **描述**: `hevc_hz_biwgt_8t_48w_msa` 处理宽48像素的水平8-tap滤波bi-weighted预测，但其主循环 `for (loop_cnt = 64; loop_cnt--;)`（第1253行）硬编码64次迭代（每次1行），完全不使用 `height` 参数。当被调用于height=32的48宽块时，函数读写比实际分配的块多32行，造成32×48=1536字节堆越界。
- **触发条件**: 构造HEVC码流，bi-weighted预测，水平运动矢量分量非零（使水平8-tap滤波器被激活），宽=48，高=32（HEVC AMP 64×32 CU的合法分割）。
- **安全影响**: 堆OOB写破坏相邻帧数据或堆结构，最坏情况RCE；OOB读泄露内存；或DoS崩溃。

## VULN: hevc_biwgt_copy_24w_msa ignores height, hardcodes 32 rows — OOB read/write
- **漏洞类别**: memory-safety
- **函数**: hevc_biwgt_copy_24w_msa()
- **行号**: 444-505 (关键语句: 472)
- **CWE**: CWE-125 / CWE-787 (Out-of-bounds Read / Out-of-bounds Write)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted HEVC media file
- **外部触发路径**: ffmpeg -i crafted.hevc -f null - -> avformat_open_input() -> ff_hevc_dsp_init_mips() [注册 ff_hevc_put_hevc_bi_w_pel_pixels24_8_msa → hevc_biwgt_copy_24w_msa] -> hevcdec.c:mc_bi_w() -> put_hevc_qpel_bi_w[6][0][0](..., block_h, ...) -> hevc_biwgt_copy_24w_msa()
- **描述**: `hevc_biwgt_copy_24w_msa` 的循环 `for (loop_cnt = 8; loop_cnt--;)`（第472行）每次处理4行，共固定处理32行，完全忽略 `height` 参数。HEVC中宽=24像素的AMP块可合法拥有height=16（如32×16 CTB分割为24×16+8×16块）。当 `height=16` 时函数读写src和dst各额外16行×24字节=384字节堆越界。
- **触发条件**: HEVC码流，双向加权预测，AMP分割使宽=24、高=16（来自32×16的CTB）。
- **安全影响**: 堆OOB写破坏帧相邻区域或堆元数据，可导致RCE/信息泄露/DoS。

## VULN: hevc_hz_biwgt_8t_24w_msa ignores height, hardcodes 32 rows — OOB read/write
- **漏洞类别**: memory-safety
- **函数**: hevc_hz_biwgt_8t_24w_msa()
- **行号**: 999-1118 (关键语句: 1049+1056)
- **CWE**: CWE-125 / CWE-787 (Out-of-bounds Read / Out-of-bounds Write)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted HEVC media file
- **外部触发路径**: ffmpeg -i crafted.hevc -f null - -> ff_hevc_dsp_init_mips() [注册 ff_hevc_put_hevc_bi_w_qpel_h24_8_msa → hevc_hz_biwgt_8t_24w_msa] -> hevcdec.c:mc_bi_w() -> put_hevc_qpel_bi_w[6][0][1](..., block_h, ...) -> hevc_hz_biwgt_8t_24w_msa()
- **描述**: 函数在进入循环前先加载第一行（第1049行），然后 `for (loop_cnt = 31; loop_cnt--;)`（第1056行）处理31行，循环后再处理最后一行（第1096-1117行）——总计恒为32行输出，与 `height` 无关。对于height=16的24宽块，函数多读/写16行×24字节=384字节。
- **触发条件**: HEVC bi-weighted预测，水平运动矢量使8-tap水平滤波器激活，宽=24，高=16。
- **安全影响**: 堆OOB写可导致帧数据或堆结构损坏，潜在RCE/DoS。

## VULN: hevc_hz_biwgt_8t_12w_msa ignores height, hardcodes 16 rows — OOB read/write
- **漏洞类别**: memory-safety
- **函数**: hevc_hz_biwgt_8t_12w_msa()
- **行号**: 822-914 (关键语句: 868)
- **CWE**: CWE-125 / CWE-787 (Out-of-bounds Read / Out-of-bounds Write)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted HEVC media file
- **外部触发路径**: ffmpeg -i crafted.hevc -f null - -> ff_hevc_dsp_init_mips() [注册 ff_hevc_put_hevc_bi_w_qpel_h12_8_msa → hevc_hz_biwgt_8t_12w_msa] -> hevcdec.c:mc_bi_w() -> put_hevc_qpel_bi_w[4][0][1](..., block_h, ...) -> hevc_hz_biwgt_8t_12w_msa()
- **描述**: `for (loop_cnt = 4; loop_cnt--;)`（第868行）每次处理4行，固定共16行，忽略 `height`。HEVC中宽=12像素的AMP块（来自16×8 CTB的非对称分割：12×8+4×8）可有height=8。调用时height=8但函数处理16行，额外读写8行×12字节=96字节堆越界。
- **触发条件**: HEVC码流，bi-weighted预测，水平运动矢量非零（8-tap H滤波器激活），AMP分割使宽=12、高=8。
- **安全影响**: 堆OOB写，潜在RCE/DoS；OOB读导致信息泄露。

## VULN: hevc_vt_biwgt_8t_12w_msa ignores height, hardcodes 16 rows — OOB read/write
- **漏洞类别**: memory-safety
- **函数**: hevc_vt_biwgt_8t_12w_msa()
- **行号**: 1631-1738 (关键语句: 1688)
- **CWE**: CWE-125 / CWE-787 (Out-of-bounds Read / Out-of-bounds Write)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted HEVC media file
- **外部触发路径**: ffmpeg -i crafted.hevc -f null - -> ff_hevc_dsp_init_mips() [注册 ff_hevc_put_hevc_bi_w_qpel_v12_8_msa → hevc_vt_biwgt_8t_12w_msa] -> hevcdec.c:mc_bi_w() -> put_hevc_qpel_bi_w[4][1][0](..., block_h, ...) -> hevc_vt_biwgt_8t_12w_msa()
- **描述**: `for (loop_cnt = 8; loop_cnt--;)`（第1688行）每次处理2行，固定共16行，忽略 `height`。对于宽=12、高=8的HEVC AMP块，额外处理8行导致堆越界读写（src0_ptr：8行×12字节=96字节；dst：8行×12字节=96字节）。
- **触发条件**: HEVC码流，bi-weighted预测，垂直运动矢量非零（8-tap V滤波器激活），AMP分割使宽=12、高=8。
- **安全影响**: 堆OOB写，潜在RCE/DoS；OOB读信息泄露。

## VULN: hevc_hv_biwgt_8t_12w_msa ignores height, hardcodes 16 rows — OOB read/write
- **漏洞类别**: memory-safety
- **函数**: hevc_hv_biwgt_8t_12w_msa()
- **行号**: 2306-2554 (关键语句: 2400, 2497)
- **CWE**: CWE-125 / CWE-787 (Out-of-bounds Read / Out-of-bounds Write)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted HEVC media file
- **外部触发路径**: ffmpeg -i crafted.hevc -f null - -> ff_hevc_dsp_init_mips() [注册 ff_hevc_put_hevc_bi_w_qpel_hv12_8_msa → hevc_hv_biwgt_8t_12w_msa] -> hevcdec.c:mc_bi_w() -> put_hevc_qpel_bi_w[4][1][1](..., block_h, ...) -> hevc_hv_biwgt_8t_12w_msa()
- **描述**: 函数分两段处理12像素宽块（左8像素+右4像素），两段均硬编码16行：第一段 `for (loop_cnt = 8; loop_cnt--;)`（第2400行）处理16行（8次×2行），第二段 `for (loop_cnt = 4; loop_cnt--;)`（第2497行）也处理16行（4次×4行）。对于HEVC AMP中12×8块，额外读写8行导致两处越界。
- **触发条件**: HEVC码流，bi-weighted预测，水平和垂直运动矢量均非零（H+V滤波），AMP分割使宽=12、高=8。
- **安全影响**: 堆OOB写两处，极大潜力RCE/DoS；OOB读信息泄露。

<!-- AUDIT_PROMPT_VERSION: 1 -->
