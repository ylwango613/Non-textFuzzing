Analysis complete. I've read the full 892-line file in three passes and traced all critical data flows. Here is my finding:

## VULN: decode_slice_thread 2-byte OOB Heap Read via hdr_size unchecked before v_data_size read
- **漏洞类别**: memory-safety
- **函数**: decode_slice_thread()
- **行号**: 659-673
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 3.1 (AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N)
- **严重程度**: Low
- **攻击向量**: crafted ProRes media file
- **外部触发路径**: ffmpeg -i crafted.mov -f null - -> avformat_open_input() -> avcodec_send_packet() -> decode_frame() -> decode_picture_header() [sets slice->data_size=6] -> decode_picture() -> avctx->execute2(..., decode_slice_thread) -> decode_slice_thread() [line 665: AV_RB16(buf+6) reads 2 bytes past slice boundary]
- **描述**: 在 `decode_slice_thread()` 中，slice 最小数据大小仅保证 ≥ 6 字节（由 `decode_picture_header()` 第 397–399 行检查）。当 `buf[0] >= 64`（即 `hdr_size = buf[0] >> 3 ≥ 8`，即 `hdr_size > 7`）时，第 665 行会执行 `v_data_size = AV_RB16(buf + 6)`，读取 `buf[6]` 和 `buf[7]`，共 2 字节。然而若该 slice 的 `data_size` 恰好等于 6，则 `buf[6]` 和 `buf[7]` 越过了该 slice 合法数据区域的末尾。合法性校验（第 669–673 行）发生在此越界读之后，虽然最终会返回 `AVERROR_INVALIDDATA`，但越界读已经发生。因 FFmpeg 包数据分配时附加了 `AV_INPUT_BUFFER_PADDING_SIZE`（64 字节）的零填充，实际读到的是填充零字节（末尾 slice）或下一 slice 的起始字节（非末尾 slice），不会导致崩溃，属于轻量级越界读。
- **触发条件**: 构造一个 ProRes 帧，其 slice index table 指定某 slice 的 data_size 字段（`AV_RB16(index_ptr + i*2)`）为 6，同时该 slice 数据的第一字节（`buf[0]`）≥ 64（使得 `buf[0] >> 3 > 7`），例如 `buf[0] = 0x40`（hdr_size=8）。可封装为 .mov/QuickTime 容器中的 ProRes 帧。
- **安全影响**: 2 字节越界堆内存读；实际读取内容为零填充字节或相邻 slice 数据，无内存损坏；影响极为有限，可作为 DoS（格式拒绝）或极小概率信息泄露。不可直接用于 RCE。

<!-- AUDIT_PROMPT_VERSION: 1 -->
