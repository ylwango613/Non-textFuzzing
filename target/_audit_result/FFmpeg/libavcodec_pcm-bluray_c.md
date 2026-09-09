Now I have a complete picture. Let me synthesize my findings.

**Key findings from the analysis:**

1. **Array bounds** for `channel_layouts[channel_layout]` and `bits_per_samples[header[3] >> 6]` are both safe (4-bit index into 16-element array; 2-bit index into 4-element array).

2. **`bytestream2_get_be16u` / `bytestream2_get_be24u`** (unchecked variants) — confirmed to be safe on little-endian paths because `samples = buf_size / sample_size` ensures total reads ≤ `buf_size`.

3. **`HAVE_BIGENDIAN` path (lines 169–171)** — `bytestream2_get_buffer(&gb, (uint8_t*)dst16, buf_size)` writes exactly `buf_size` bytes to the destination. However, the frame buffer is allocated with `frame->nb_samples = buf_size / sample_size` (integer division), so its size is `(buf_size / sample_size) * sample_size` bytes — i.e., `buf_size` rounded down to a multiple of `sample_size`. If a crafted packet has `buf_size % sample_size != 0`, up to `sample_size − 1` bytes are written past the end of the heap-allocated frame buffer (max 7 bytes for 4.0/2.2 channel configs).

4. **Little-endian paths and all other channel-remapping cases** — correctly bounded; writes match frame buffer size exactly.

---

## VULN: Heap Buffer Overflow in Big-Endian S16 pcm_bluray Decode via Non-Aligned Packet Size
- **漏洞类别**: memory-safety
- **函数**: pcm_bluray_decode_frame()
- **行号**: 148-175
- **CWE**: CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 5.3 (AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted Blu-ray PCM media file
- **外部触发路径**: `ffmpeg -i <crafted_file> -f null -` → `avformat_open_input()` → demuxer delivers PCM Blu-ray audio packet → `avcodec_send_packet()` → `pcm_bluray_decode_frame()` → `bytestream2_get_buffer(&gb, (uint8_t*)dst16, buf_size)` [line ~170, HAVE_BIGENDIAN path]
- **描述**: 在 `pcm_bluray_decode_frame()` 中，`frame->nb_samples = samples = buf_size / sample_size`（整除），因此 `ff_get_buffer` 分配的输出帧缓冲区大小为 `(buf_size / sample_size) * sample_size` 字节（即 `buf_size` 向下对齐到 `sample_size` 的整数倍）。随后，在 `#if HAVE_BIGENDIAN` 编译分支（适用于 STEREO、AV_CH_LAYOUT_4POINT0、AV_CH_LAYOUT_2_2 + AV_SAMPLE_FMT_S16 组合），代码调用 `bytestream2_get_buffer(&gb, (uint8_t*)dst16, buf_size)` 向 `dst16`（帧缓冲区）写入整 `buf_size` 字节。若 `buf_size % sample_size != 0`，写入量超过帧缓冲区末端，造成堆越界写入最多 `sample_size - 1` 字节（STEREO S16 最多 3 字节，4POINT0/2_2 S16 最多 7 字节），写入内容为攻击者控制的数据包尾部字节。
- **触发条件**: 攻击者构造一个 Blu-ray PCM 音频数据包，令其净负载长度（去除 4 字节头后的 `buf_size`）不是 `sample_size` 的整数倍（如 STEREO S16 令 `buf_size = 4k+1` 至 `4k+3`）。该数据包可封装于 Blu-ray MPEG-TS（`.m2ts`）文件中；仅在 big-endian 目标平台（如 PowerPC、MIPS BE、SPARC）上的 FFmpeg 构建触发此分支。
- **安全影响**: 最坏情况下，在大端平台上，最多 7 字节攻击者可控数据写入帧缓冲区末端之后的堆内存，可能破坏堆元数据或相邻分配对象，理论上可被利用实现任意代码执行（RCE）；在多数小端平台（x86/ARM）上此分支不编译，无影响。

<!-- AUDIT_PROMPT_VERSION: 1 -->
