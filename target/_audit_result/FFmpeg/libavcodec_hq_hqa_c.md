I now have a complete picture of the code. Let me document the analysis findings precisely.

**Tracing the `data_size` accounting error:**

In `hq_hqa_decode_frame` (line 348):
```c
data_size = bytestream2_get_bytes_left(gbc);  // measured BEFORE reading 4-byte tag
...
unsigned tag = bytestream2_get_le32u(gbc);    // tag consumed, gbc advances 4 bytes
ret = hq_decode_frame(ctx, pic, gbc, tag >> 24, data_size);  // data_size still includes those 4 bytes
```

In `hq_decode_frame` (line 140):
```c
const uint8_t *src = gbc->buffer;  // src is now 4 bytes PAST start of data_size
```

Valid byte range from `src` = `data_size - 4` bytes (indices `[0, data_size-5]`). But the check at line 178 is `slice_off[slice+1] > data_size`, which allows `slice_off[slice+1] = data_size`. This means `init_get_bits` is handed a bitstream that declares data at `src + data_size`, which is `avpkt->data + avpkt->size + 4` — **4 bytes past the end of the packet buffer**.

The identical flaw exists in `hqa_decode_frame` (line 305) by the same accounting error.

In normal FFmpeg operation packets carry `AV_INPUT_BUFFER_PADDING_SIZE = 64` zeroed bytes past `avpkt->size`, so the OOB read is into padding (reads zeros, wrong decode result rather than crash). Without that padding — e.g., `av_packet_from_data`, custom demuxers, or fuzz harnesses — this is a heap OOB read.

---

## VULN: Off-by-4 OOB Read in HQ/HQA Slice Offset Bounds Check
- **漏洞类别**: memory-safety
- **函数**: hq_decode_frame(), hqa_decode_frame()
- **行号**: 176-184 (hq_decode_frame), 302-311 (hqa_decode_frame)
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 5.4 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:L)
- **严重程度**: Medium
- **攻击向量**: crafted media file (Canopus HQ/HQA video stream)
- **外部触发路径**: ffmpeg -i crafted.avi -f null - → avcodec_decode_video2() → hq_hqa_decode_frame() → hq_decode_frame() / hqa_decode_frame() → init_get_bits(src + slice_off[slice], ...) with OOB end pointer → bit-reading past avpkt->data+avpkt->size
- **描述**: `data_size` is captured via `bytestream2_get_bytes_left(gbc)` **before** the 4-byte format tag (`CUV`/`HQA1`) is consumed from the bytestream in `hq_hqa_decode_frame()`. The tag is then read (`bytestream2_get_le32u`), advancing `gbc->buffer` by 4 bytes, before passing `gbc` and the now-stale `data_size` to the per-format decode functions. Inside both `hq_decode_frame()` and `hqa_decode_frame()`, `src = gbc->buffer` points **4 bytes past** the position that was used to compute `data_size`, so the valid byte range from `src` is `[0, data_size − 5]`, not `[0, data_size]`. The slice-end bound check `slice_off[slice + 1] > data_size` (line 178 and line 305) is therefore off by 4: an attacker-controlled offset of exactly `data_size` passes the check. `init_get_bits()` is then called with a declared buffer of `(data_size − slice_off[slice]) * 8` bits whose declared end (`src + data_size`) lies **4 bytes past the packet's allocated memory**. When the decoder subsequently reads bits from the tail of that slice (via `hq_decode_block` / `hqa_decode_slice`), it accesses those 1–4 out-of-bounds bytes.
- **触发条件**: 构造一个 Canopus HQ 或 HQA 格式的视频帧，其中最后一个 slice 的结束偏移（be24 或 be32 字段）设置为 `data_size + 4`（即等于 tag 前测量的帧剩余字节数加 4）。该值通过所有三个有效性检查（最小值检查、顺序检查、`> data_size` 检查均通过），导致 `init_get_bits` 初始化一个声明末端超出 `avpkt->data + avpkt->size` 的比特流。只要该 slice 包含至少一个宏块并且解码器消耗了接近声明末端的比特，OOB 读就会发生。
- **安全影响**: 最坏情况（无 AV_INPUT_BUFFER_PADDING_SIZE 内存填充，如自定义调用方或 fuzz 场景）：堆 OOB 读 1–4 字节，可能暴露相邻堆对象的内容（信息泄露），或在内存页边界处触发 SIGSEGV（DoS）。在标准 FFmpeg 构建中，由于 avpkt->data 之后固定分配 64 字节的零填充，实际影响通常为读取全零字节导致解码错误输出而非崩溃，但该填充假设并非所有调用路径均有保障。

<!-- AUDIT_PROMPT_VERSION: 1 -->
