关键分析已完成。现在精确计算溢出边界：

- `packet_size = 4 + nb_blocks * (2 + 3*64*64)` = 每块分配 **12290** 字节（含 2 字节头）
- `zsize = 3 * block_width * block_height + 12` = `12300` 字节传给 compress2 作为输出上界
- `ff_alloc_packet` 用 `av_fast_padded_malloc` 实际分配 `packet_size + 64`（AV_INPUT_BUFFER_PADDING_SIZE）

per-block 差额 = **12 字节**。溢出条件：`nb_blocks * 12 > 64`，即 **nb_blocks ≥ 6**（对应约 193×64 像素以上的图像）。

1920×1080 实例：nb_blocks = 510，最大溢出 = 510×12 - 64 = **6056 字节**，远超 padding。

---

## VULN: Heap Buffer Overflow in FlashSV Encoder via compress2 Output Overrun
- **漏洞类别**: memory-safety
- **函数**: encode_bitstream()
- **行号**: 133-204（核心：178-188）
- **CWE**: CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted video input to server-side FlashSV transcoding pipeline
- **外部触发路径**: `ffmpeg -i crafted_input.mp4 -vcodec flashsv output.flv` → `flashsv_encode_frame()` → `ff_alloc_packet(avctx, pkt, s->packet_size)` → `encode_bitstream()` → `compress2(ptr+2, &zsize, s->tmpblock, ...)` OOB write
- **描述**: `flashsv_encode_init()` 第 123 行计算 `s->packet_size = 4 + nb_blocks * (2 + 3 * BLOCK_WIDTH * BLOCK_HEIGHT)`，即每块分配 `12290` 字节（2 字节大小头 + `3*64*64=12288` 字节压缩数据）。`encode_bitstream()` 第 178 行却将 `zsize = 3 * block_width * block_height + 12 = 12300` 传递给 `compress2` 作为输出缓冲区上界。两者相差 **12 字节**。`ff_alloc_packet` 通过 `av_fast_padded_malloc` 额外附加 `AV_INPUT_BUFFER_PADDING_SIZE=64` 字节，但当 `nb_blocks ≥ 6` 时（即总差额 `nb_blocks*12 > 64`），compress2 被授权向最后若干个块的 `ptr+2` 写入最多 12300 字节，而堆缓冲区实际可用空间已不足 12300 字节，导致 compress2 向堆边界外写入最多 12 字节每块的越界数据。对于 1920×1080 的输入，nb_blocks=510，最大溢出量为 **6056 字节**；对于最大允许尺寸 4095×4095（nb_blocks=4096），最大溢出量约 **49088 字节**。
- **触发条件**: 攻击者提供一个视频输入文件，使 FFmpeg 以 FlashSV 编码器编码尺寸满足 `nb_blocks ≥ 6`（即约 193×64 像素及以上，几乎所有实际视频分辨率均满足）的帧，且帧内容不可压缩（如随机噪点像素），使 compress2 输出接近 zsize 上限，累积越界写超出堆 padding 范围。
- **安全影响**: 攻击者可控的堆越界写入可破坏堆元数据或相邻对象，在服务端自动转码场景下（如云视频处理服务）可能导致远程代码执行（RCE）；最坏情况下实现任意代码执行，或造成进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
