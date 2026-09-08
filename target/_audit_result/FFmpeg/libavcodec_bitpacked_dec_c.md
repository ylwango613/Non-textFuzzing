`av_image_fill_arrays` returns the required buffer size on success — confirmed it does NOT verify that `src` is large enough. Now I have everything I need.

**Analysis summary:**

In `bitpacked_decode_uyvy422` (lines 40-60):
- `av_image_fill_arrays` returns the required buffer size as a **positive** `ret` on success.
- The code checks `if (ret < 0)` but **never compares `ret` to `avpkt->size`**.
- `frame->data[0]` is set to point directly into `avpkt->data` (passthrough path).
- If the attacker provides a crafted packet where `avpkt->size < width * height * 2`, the frame's data pointers overshoot the valid buffer.
- Any downstream consumer (filter, encoder, format output) that reads the full frame will perform an **out-of-bounds heap read** beyond the packet's allocated buffer.

In contrast, `bitpacked_decode_yuv422p10` correctly validates `frame_size > packet_size` (lines 75-76) before any data access.

---

## VULN: Missing packet size check before av_image_fill_arrays in bitpacked_decode_uyvy422
- **漏洞类别**: memory-safety
- **函数**: bitpacked_decode_uyvy422()
- **行号**: 40-60
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted media file (AVI/MOV with UYVY codec tag)
- **外部触发路径**: `ffmpeg -i crafted.avi -f null -` → `avformat_open_input()` → `avcodec_send_packet()` → `bitpacked_decode()` → `bitpacked_decode_uyvy422()` → downstream frame consumer (lavfi filter / encoder) reads `frame->data[0]` OOB
- **描述**: 在 `bitpacked_decode_uyvy422` 中，调用 `av_image_fill_arrays` 后，其返回值 `ret` 代表容纳该帧所需的最小字节数（`width * height * 2` for UYVY422）。代码仅检查 `ret < 0`（即 API 错误），而**未将 `ret` 与 `avpkt->size` 比较**。`frame->data[0]` 被直接设置为 `avpkt->data`（passthrough 路径，不拷贝）。当 `avpkt->size < width * height * 2` 时，`frame->data[0]` 合法，但整帧数据区超出 AVPacket 底层缓冲区边界，任何后续读帧操作（编码器、lavfi 过滤器、格式输出层）均会产生 **堆越界读（heap out-of-bounds read）**，可读取 AVPacket 缓冲区之后的任意堆内容。相比之下，同文件的 `bitpacked_decode_yuv422p10` 在第 75 行有明确的 `frame_size > packet_size` 校验，说明此校验被有意跳过是设计缺陷。
- **触发条件**: 攻击者构造一个 AVI（或 MOV/QuickTime）容器文件，其视频轨 codec tag 为 `UYVY`、`bits_per_coded_sample=16`、`pix_fmt=AV_PIX_FMT_UYVY422`，但视频帧数据包（AVPacket）大小显著小于 `width * height * 2` 字节（例如 `width=1920, height=1080` 需 4,147,200 字节，而攻击者提供仅 128 字节的包）。用户以 `ffmpeg -i crafted.avi output.mp4` 运行即可触发。
- **安全影响**: 最坏情况：堆越界读可泄露 FFmpeg 进程堆上的敏感内存内容（如其他帧数据、解密密钥、指针地址用于绕过 ASLR），以及必然的进程崩溃（DoS）。若堆布局可被进一步控制（配合其他原语），信息泄露可辅助 RCE 利用链构造。

<!-- AUDIT_PROMPT_VERSION: 1 -->
