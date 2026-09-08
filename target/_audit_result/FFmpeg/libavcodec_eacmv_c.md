Now I have enough context to finalize the analysis. Let me trace the key computation:

**Line 189 bounds check analysis:**
- `size > buf_end - buf - EA_PREAMBLE_SIZE` → allows `size = buf_size - 8` (maximum)
- After `buf += size` (line 191): buf is at `original + buf_size - 8`, leaving exactly 8 bytes to buf_end
- After the **unconditional** `buf += EA_PREAMBLE_SIZE` (line 197): buf == buf_end exactly
- `buf[0]` at line 198 → 1-byte OOB read

The check at line 189 does not account for the mandatory second advance at line 197. The correct check should be `size > buf_end - buf - 2*EA_PREAMBLE_SIZE`.

**Mitigating factor:** FFmpeg mandates `AV_INPUT_BUFFER_PADDING_SIZE` (64 bytes) of zero-padding after `avpkt->data`, so in normal FFmpeg usage the byte read falls in zeroed padding and does not crash. In non-standard API usage (raw decoder invocation without padding), this is a true heap OOB read.

## VULN: Off-by-8 Bounds Check in cmv_decode_frame Enables 1-Byte OOB Read
- **漏洞类别**: memory-safety
- **函数**: cmv_decode_frame()
- **行号**: 189-198
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 3.3 (AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N)
- **严重程度**: Low
- **攻击向量**: crafted EA CMV media file
- **外部触发路径**: `ffmpeg -i <crafted.cmv> -f null -` → `avformat_open_input()` → EA demuxer → `avcodec_send_packet()` → `cmv_decode_frame()` → OOB read at line 198
- **描述**: 在 `cmv_decode_frame` 函数中，对 MVIh 头块 `size` 字段的边界检查（第 189 行）为 `size > buf_end - buf - EA_PREAMBLE_SIZE`，即允许 `size` 最大等于 `buf_size - 8`。随后第 191 行执行 `buf += size`，第 197 行无条件再次执行 `buf += EA_PREAMBLE_SIZE`（跳过视频数据块的 8 字节 preamble）。当 `size` 恰好为 `buf_size - 8` 时，两次累加后 `buf` 精确等于 `buf_end`，第 198 行的 `buf[0]` 解引用产生 1 字节越界读。根本原因是边界检查未计入第二次强制性 `+= EA_PREAMBLE_SIZE`，正确检查应为 `size > buf_end - buf - 2*EA_PREAMBLE_SIZE`。
- **触发条件**: 构造一个 EA CMV 文件，其中 MVIh chunk 的 `size` 字段（偏移 4-7，little-endian）设置为 `total_packet_size - EA_PREAMBLE_SIZE`（即恰好消耗掉除第二个 preamble 之外的所有数据），且 MVIh 头部包含至少 16 字节以通过 `cmv_process_header` 的截断检查。
- **安全影响**: 正常使用 FFmpeg 公共 API 时，因 `AVPacket` 数据后强制附加 64 字节零填充（`AV_INPUT_BUFFER_PADDING_SIZE`），越界读取的是零字节，实际危害被缓解为功能性错误（AVERROR_INVALIDDATA 提前返回）。在直接调用解码器 API 且未添加填充的场景下（如自定义嵌入式集成），可读取一字节堆内存越界数据，造成信息泄露；若该字节恰好为奇数，还会绕过后续大小检查并进入解码逻辑，可能引发进一步的内存访问异常（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
