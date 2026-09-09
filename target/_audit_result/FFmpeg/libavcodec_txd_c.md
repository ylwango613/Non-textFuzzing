`AV_PIX_FMT_RGBA` has no special case in `avcodec_align_dimensions2`, confirmed. This means `h_align=1`, and the frame buffer is allocated for exactly `h` rows with no rounding to a multiple of 4.

**Summary of the confirmed vulnerability:**

- `dxt1_block_internal` (texturedsp.c:96–103) and `dxt3_block_internal` (texturedsp.c:150–167) unconditionally loop `y` from 0 to 3, writing 4 full rows per call at `dst + y*stride`.
- The output frame (`ff_get_buffer`, get_buffer.c:87–111) is allocated for exactly `h` rows + small trailing padding (`16 + STRIDE_ALIGN − 1` bytes ≈ 79 bytes).
- For any `h` not divisible by 4 (h ≡ 1, 2, or 3 mod 4), the last DXT block row `j = ⌊(h−1)/4⌋ × 4` causes the block function to write rows `j+1` through `j+3` beyond the image height, overflowing the allocated buffer by up to 3×stride bytes per column.
- For `h=1`, `w=65535`: overflow = 3 × 262 144 = 786 432 bytes of contiguous heap corruption.
- No validation of `h % 4` exists anywhere in `txd_decode_frame`.

## VULN: Heap OOB Write in DXT1/DXT3 Decode for Non-Multiple-of-4 Height
- **漏洞类别**: memory-safety
- **函数**: txd_decode_frame() → dxt1_block_internal() / dxt3_block_internal()
- **行号**: 124-139 (decode loop); root cause at 94-101 (ff_get_buffer allocation vs. block-stride write)
- **CWE**: CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted media file (.txd)
- **外部触发路径**: ffmpeg -i crafted.txd -f null - → avcodec_send_packet() → txd_decode_frame() → ff_get_buffer() [allocates h rows for AV_PIX_FMT_RGBA, no 4-row alignment] → dxt1_block()/dxt3_block() [unconditionally writes 4 rows per block call] → dxt1_block_internal()/dxt3_block_internal() [heap OOB write past end of frame buffer]
- **描述**: `avcodec_align_dimensions2()` does not align `AV_PIX_FMT_RGBA` height to any multiple of 4 (`h_align=1` for RGBA, confirmed in utils.c:141-342), so `ff_get_buffer` allocates exactly `linesize × h + 79` bytes for the output frame. The DXT decode loops (lines 124-139) step in blocks of 4 rows (`j += 4`) and call `dxtc.dxt1_block(ptr + i*4 + j*stride, stride, src)`. Both `dxt1_block_internal` and `dxt3_block_internal` unconditionally iterate `y` from 0 to 3, advancing `dst += stride` each iteration, writing 4 rows regardless of remaining image height. For any `h` where `h % 4 != 0`, the last block row `j_last = ⌊(h−1)/4⌋ × 4` causes the block function to write 1–3 rows beyond the allocated buffer (e.g., h=1 → j_last=0 → writes rows 1, 2, 3 beyond the 1-row buffer; h=2 → writes rows 2, 3 beyond the 2-row buffer). The overflow magnitude per block-column is 1–3 rows × stride bytes, totalling up to 3 × linesize × ⌈w/4⌉ bytes. For `w=65535, h=1`, this equals 786 432 bytes of contiguous heap overwrite.
- **触发条件**: 构造 TXD 文件：version=8 或 9；depth=0x10（16）使解码器进入 DXT 路径；d3d_format=0x31545844（DXT1）或 0x33545844（DXT3）；高度 h 设为不能被 4 整除的值（如 h=1、2、3、5、6、7…）；宽度 w 可取任意合法 uint16 值；packet 数据满足第 78-83 行的最小字节数校验即可（对 h=1,w=4 仅需 payload≥100 字节）。
- **安全影响**: 堆缓冲区溢出，溢出内容为攻击者可控的 DXT 解码输出（16 位调色板混合像素值）。可覆盖相邻堆块元数据或对象，进而实现任意代码执行（RCE）；同时可在崩溃前泄露堆布局信息。受影响的所有处理 TXD 格式图像的 FFmpeg 版本均受影响。

<!-- AUDIT_PROMPT_VERSION: 1 -->
