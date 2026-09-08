The analysis is complete. I've confirmed five distinct hardcoded-iteration bugs where the `height` parameter is completely ignored. Here is the final report:

---

## VULN: copy_width12_msa ignores height — OOB heap write (always 16 rows)
- **漏洞类别**: memory-safety
- **函数**: copy_width12_msa()
- **行号**: 146-158
- **CWE**: CWE-787 (Out-of-bounds Write)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted media file (HEVC/H.265)
- **外部触发路径**: `ffmpeg -i <crafted.hevc> -f null -` → `avformat_open_input()` → `avcodec_send_packet()` → `ff_hevc_decode_nal_slice()` → HEVC chroma motion compensation → `ff_hevc_put_hevc_uni_pel_pixels12_8_msa()` → `copy_width12_msa()` [OOB write]
- **描述**: `copy_width12_msa` 接收 `height` 参数但完全不使用它。函数体硬编码两次 `LD_UB8`/`ST12x8_UB` 调用，无条件读取并写入恰好 16 行（第 152–157 行），不管 `height` 实际值是多少。在 HEVC 4:2:0 格式中，24×8 或 24×4 亮度 PU 产生对应 12×4 或 12×8 色度块；HEVC 解码器以 `height=4` 或 `height=8` 调用该函数，但函数始终写入 16 行，导致色度帧缓冲区越界写入。
- **触发条件**: 构造一个包含 24×8（或 24×4）亮度运动补偿预测单元的 HEVC 码流（Asymmetric Motion Partitioning），使解码器对 12 像素宽色度分量调用 `copy_width12_msa(height=4)` 或 `copy_width12_msa(height=8)`，函数将在分配缓冲区末尾之外额外写入 8 或 12 行。
- **安全影响**: 堆越界写入，写入的数据为解码帧像素（攻击者可通过图像内容控制部分字节）；最坏情况下可覆盖相邻堆元数据或函数指针，导致远程代码执行（RCE）。

---

## VULN: copy_width24_msa ignores height — OOB heap write (always 32 rows)
- **漏洞类别**: memory-safety
- **函数**: copy_width24_msa()
- **行号**: 196-217
- **CWE**: CWE-787 (Out-of-bounds Write)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted media file (HEVC/H.265)
- **外部触发路径**: `ffmpeg -i <crafted.hevc> -f null -` → `avformat_open_input()` → `avcodec_send_packet()` → `ff_hevc_decode_nal_slice()` → HEVC chroma motion compensation → `ff_hevc_put_hevc_uni_pel_pixels24_8_msa()` → `copy_width24_msa()` [OOB write]
- **描述**: `copy_width24_msa` 接收 `height` 参数但完全忽略它，而是以硬编码的 `for (cnt = 4; cnt--)` 循环执行，每次迭代处理 8 行，共计固定写入 32 行（第 204–215 行）。在 HEVC 4:2:0 中，48×16 亮度 PU 产生 24×8 色度块；以 `height=8` 调用时，函数多写 24 行；以 `height=4` 调用时多写 28 行，均超出分配缓冲区边界。
- **触发条件**: 构造包含 48×8 或 48×16 亮度 PU 的 HEVC 码流（4:2:0），使解码器以 `height=4` 或 `height=8` 调用 `copy_width24_msa`，函数固定写入 32 行导致越界。
- **安全影响**: 堆越界写入，可覆盖相邻帧缓冲区或堆管理结构，最坏情况导致 RCE；最低限度造成解码器崩溃（DoS）。

---

## VULN: common_hz_8t_48w_msa ignores height — OOB heap write (always 64 rows)
- **漏洞类别**: memory-safety
- **函数**: common_hz_8t_48w_msa()
- **行号**: 741-825
- **CWE**: CWE-787 (Out-of-bounds Write)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted media file (HEVC/H.265)
- **外部触发路径**: `ffmpeg -i <crafted.hevc> -f null -` → `avformat_open_input()` → `avcodec_send_packet()` → `ff_hevc_decode_nal_slice()` → HEVC luma/chroma horizontal qpel MC → `ff_hevc_put_hevc_uni_qpel_h48_8_msa()` → `common_hz_8t_48w_msa()` [OOB write]
- **描述**: `common_hz_8t_48w_msa` 接收 `height` 参数但完全不使用，函数内部以硬编码 `for (loop_cnt = 64; loop_cnt--)` 循环（第 766 行）无条件处理 64 行。在 HEVC 中，96×32 亮度 PU 的水平 qpel 滤波（48 宽色度或 48 宽亮度子块）会以 `height=32` 调用该函数，但函数仍写入 64 行，造成 32 行越界。
- **触发条件**: 构造包含 48 像素宽、height 小于 64 的运动补偿块的 HEVC 码流（如 48×32 亮度或 96×32 亮度 4:2:0 色度），使解码器以 `height<64` 调用该函数，函数固定处理 64 行导致 OOB 写。
- **安全影响**: 堆越界写，写入位置超出帧缓冲区末尾；可利用连续内存布局覆盖相邻分配块，在最坏情况下导致 RCE。

---

## VULN: hevc_hv_uni_4t_6w_msa ignores height — OOB heap write (always 8 rows)
- **漏洞类别**: memory-safety
- **函数**: hevc_hv_uni_4t_6w_msa()
- **行号**: 3409-3526
- **CWE**: CWE-787 (Out-of-bounds Write)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted media file (HEVC/H.265)
- **外部触发路径**: `ffmpeg -i <crafted.hevc> -f null -` → `avformat_open_input()` → `avcodec_send_packet()` → `ff_hevc_decode_nal_slice()` → HEVC chroma epel HV MC → `ff_hevc_put_hevc_uni_epel_hv6_8_msa()` → `hevc_hv_uni_4t_6w_msa()` [OOB write]
- **描述**: `hevc_hv_uni_4t_6w_msa` 接收 `height` 参数但函数体完全不引用它（第 3409–3526 行无任何循环或 height 判断）。函数固定读取 11 行源数据（`LD_SB3` 预取 3 行后再读 8 行，共 11 行）并向目标缓冲区写入恰好 8 行输出（`ST_W8` / `ST_H8`）。对于 HEVC 4:2:0 中 12×8 亮度 PU 产生的 6×4 色度块（height=4），函数仍写入 8 行，超出仅分配 4 行的缓冲区边界 4 行。
- **触发条件**: 构造包含 12×8 亮度 PU（色度为 6×4）且需要两方向 epel 内插的 HEVC 码流，使解码器以 `height=4` 调用 `hevc_hv_uni_4t_6w_msa`，函数多写 4 行越界。
- **安全影响**: 堆越界写，可能破坏相邻帧缓冲区或堆元数据，最坏情况下导致 RCE。

---

## VULN: common_hz_4t_24w_msa ignores height — OOB heap write (always 32 rows)
- **漏洞类别**: memory-safety
- **函数**: common_hz_4t_24w_msa()
- **行号**: 2403-2484
- **CWE**: CWE-787 (Out-of-bounds Write)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted media file (HEVC/H.265)
- **外部触发路径**: `ffmpeg -i <crafted.hevc> -f null -` → `avformat_open_input()` → `avcodec_send_packet()` → `ff_hevc_decode_nal_slice()` → HEVC chroma epel horizontal MC → `ff_hevc_put_hevc_uni_epel_h24_8_msa()` → `common_hz_4t_24w_msa()` [OOB write]
- **描述**: `common_hz_4t_24w_msa` 接收 `height` 参数但完全不使用，函数以硬编码 `for (loop_cnt = 8; loop_cnt--)` 循环（第 2426 行），每次迭代处理 4 行，固定向目标写入 32 行。在 HEVC 4:2:0 中，48×16 亮度 PU 产生 24×8 色度块；解码器以 `height=8` 调用该函数，函数多写 24 行越界；以 `height=4` 调用时多写 28 行。
- **触发条件**: 构造包含 48×8 或 48×16 亮度 PU 且使用水平 epel 插值的 HEVC 码流，使解码器对 24 宽色度块以 `height=8`（或 `height=4`）调用该函数，触发越界写。
- **安全影响**: 堆越界写，将解码像素数据写入帧缓冲区分配范围外，可能破坏相邻对象；在精心设计的堆布局下可导致 RCE，亦可确定导致进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
