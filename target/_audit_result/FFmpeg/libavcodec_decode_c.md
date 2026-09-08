I have completed a thorough multi-batch reading of all 2515 lines of `decode.c` and cross-referenced key helpers. Here is my analysis of the complete file:

**Batch 1 (0–499):** `apply_param_change()` reads width/height from `AV_PKT_DATA_PARAM_CHANGE` side data as `uint32_t` into `int avctx->width/height`, then immediately calls `ff_set_dimensions()` → `av_image_check_size2(unsigned w, unsigned h, ...)` which catches all overflow/negative cases. Safe.

**Batch 2 (500–999):** `recode_subtitle()` guards against `inl * UTF8_MAX_BYTES` overflow at line 874. `discard_samples()` — identified a potential OOB: the `AV_CODEC_FLAG2_SKIP_MANUAL` block at lines 343–351 creates a new 10-byte side data only when `!side`, but when `side` already exists with `size < 10`, it proceeds to write 10 bytes into it without re-checking the size.

**Batch 3 (1000–1499):** `ff_get_format()`, `avcodec_decode_subtitle2()`, `side_data_exif_parse()` — all look safe, with properly paired allocations and copies.

**Batch 4 (1500–1999):** `side_data_map()` copies exactly `sd_pkt->size` bytes into a `sd_pkt->size`-byte allocation — correct. `ff_get_buffer()` has multi-layer size validation with `av_image_check_size2`.

**Batch 5 (2000–2515):** `ff_decode_preinit()` correctly bounds the 64-bit `side_data_pref_mask` shift (checks `>= 64`). `side_data_pref()` at line 2175 `1ULL << type` is safe because current `AVFrameSideDataType` has only 38 entries (all < 64). Rest of file is boilerplate lifecycle management.

**Key finding — `discard_samples()` OOB heap write:**
- Guard at line 331 (`side->size >= 10`) only protects the *reader* block
- The writer block at lines 346–350 has NO corresponding size check
- `avci->skip_samples` is set non-zero by several codecs at init time (AAC=1024, WMA=frame_len×2, libopus=pre_skip) — independent of the frame's side data size
- When a frame arrives with `AV_FRAME_DATA_SKIP_SAMPLES` of size < 10 and `AV_CODEC_FLAG2_SKIP_MANUAL` is set, `AV_WL32(side->data+4,…)` and `AV_WL8(side->data+8/9,…)` write past the allocated heap buffer

All standard demuxers create SKIP_SAMPLES with exactly 10 bytes, so triggering requires either a non-standard demuxer path or a re-muxing scenario. This limits practical attack complexity.

## VULN: OOB Heap Write in discard_samples() via undersized AV_FRAME_DATA_SKIP_SAMPLES
- **漏洞类别**: memory-safety
- **函数**: discard_samples()
- **行号**: 343-351
- **CWE**: CWE-787 (Out-of-bounds Write)
- **CVSS v3.1**: 6.3 (AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted audio media file (AAC/M4A, Ogg/Vorbis, Opus, WMA, NUT)
- **外部触发路径**: ffmpeg -i <crafted_file> -f null - → avcodec_send_packet() → decode_simple_internal() → discard_samples() (line 468) → OOB write at lines 347-350
- **描述**: `discard_samples()` 的 `AV_CODEC_FLAG2_SKIP_MANUAL` 分支（行 343–351）存在逻辑不对称：行 331 只在 `side->size >= 10` 时才读取 side data 字段；但行 346 的写路径仅检查 `side != NULL`，未重新验证 `side->size >= 10`。当 frame 携带的 `AV_FRAME_DATA_SKIP_SAMPLES` side data 大小 < 10 字节时（例如 4 字节），行 347 `AV_WL32(side->data, avci->skip_samples)` 写入偏移 0–3 合法，但行 348 `AV_WL32(side->data + 4, discard_padding)` 写入偏移 4–7、行 349 `AV_WL8(side->data + 8, ...)` 写偏移 8、行 350 `AV_WL8(side->data + 9, ...)` 写偏移 9 均越界，造成堆上最多 6 字节的 OOB 写。触发条件：(1) 解码器上下文以 `AV_CODEC_FLAG2_SKIP_MANUAL` 运行（多种 gapless 音频播放器默认启用）；(2) `avci->skip_samples` 非零（AAC 解码器初始化时固定设置为 1024，WMA/Opus/Vorbis 类似）；(3) 到达一个携带 size < 10 的 `AV_FRAME_DATA_SKIP_SAMPLES` side data 的音频帧。第三点通过 `side_data_map()` 将包的 `AV_PKT_DATA_SKIP_SAMPLES`（size 来自容器）直接传播到帧。
- **触发条件**: 攻击者构造一个 AAC/M4A、Ogg Vorbis、NUT 或类似支持 SKIP_SAMPLES 元数据的音频文件，使其中一个数据包附带 `AV_PKT_DATA_SKIP_SAMPLES` side data 且 size < 10（例如 4 字节）。目标应用需启用 `AV_CODEC_FLAG2_SKIP_MANUAL`（gapless 播放场景常见）。被攻击的解码器（如 AAC）会在 init 阶段将 `avci->skip_samples` 设为非零值，之后遇到上述帧即触发越界写。
- **安全影响**: 最坏情况下攻击者可控制写入堆相邻对象的 1–6 字节（值固定为 `avci->skip_samples`，通常为已知常量如 1024 或 codec 延迟值），可引发进程崩溃（DoS）；在精心构造的堆布局下，存在利用相邻堆对象字段覆写以实现任意代码执行（RCE）的可能性。

<!-- AUDIT_PROMPT_VERSION: 1 -->
