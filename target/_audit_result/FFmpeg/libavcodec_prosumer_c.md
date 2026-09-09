The vulnerability is confirmed. The arithmetic proves:
- `avctx->width=65536, avctx->height=43692` → `s->size` wraps to 131072 (128KB via 32-bit unsigned overflow)
- `av_malloc(131072)` allocates only 128KB
- `vertical_predict` then writes up to offset ~4.3 GB past the start → OOB write by ~4GB

## VULN: Integer Overflow in decode_init Causes Heap Buffer Overflow in prosumer decoder
- **漏洞类别**: memory-safety
- **函数**: decode_init() / vertical_predict() (called via decode_frame())
- **行号**: 339-345 (overflow), 167 (OOB write in vertical_predict), 177 (OOB read in decode_frame)
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted media file (AVI container with ProSumer video stream)
- **外部触发路径**: `ffmpeg -i crafted.avi -f null -` → `avformat_open_input()` → `avcodec_open2()` → `decode_init()` [integer overflow in s->size] → `avcodec_send_packet()` → `decode_frame()` → `vertical_predict()` [OOB heap write]
- **描述**: In `decode_init()` (line 339–345), `s->stride` is declared as `unsigned` (32-bit) and `s->size` is likewise `unsigned`. The computation `s->size = avctx->height * s->stride` is a plain 32-bit unsigned multiplication. When `avctx->height * s->stride` exceeds `UINT32_MAX`, the product silently wraps around (e.g., width=65536 height=43692 → stride=98304, 43692×98304=4,295,098,368 wraps to 131,072). `av_malloc(131072)` succeeds but allocates only 128 KB. In `decode_frame()`, `vertical_predict()` is then called with the full `avctx->height - 1` row count and the real `s->stride`; it advances the destination pointer by `(avctx->height-1) * s->stride ≈ 4.3 GB` past the allocation base, performing an out-of-bounds heap write of controlled data. Additionally, the frame copy loop at line 177 computes `src = s->decbuffer + (avctx->height-1-i) * s->stride` without any bounds guard, producing an OOB heap read over the same range. Neither `decode_init` nor any caller invokes `av_image_check_size` or any equivalent bounds check on the supplied dimensions.
- **触发条件**: 攻击者构造一个 AVI 文件，其 `BITMAPINFOHEADER` 中的 `biWidth`/`biHeight` 设置为使 `avctx->height × s->stride` 超过 `UINT32_MAX` 的值（例如 `biWidth=65536, biHeight=43692`），然后让受害者用 `ffmpeg -i crafted.avi` 处理该文件，或通过任何调用 FFmpeg 解码 API 的应用（播放器、转码服务等）传递该文件。
- **安全影响**: 攻击者控制的数据（解压后的视频帧内容）被写入堆中远超分配边界之外的位置，可覆盖相邻堆元数据和其他对象。结合 FFmpeg 进程中丰富的堆对象（函数指针、vtable 指针等），可进一步构造任意代码执行（RCE）原语。即使最坏情况下无法 RCE，也能导致进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
