Now I have all the context I need. Let me analyze the arithmetic carefully:

**Key computation in `encode_frame` (v210enc.c:72-73) and `v210_template.c:29-31`:**
- `int aligned_width = ((avctx->width + 47) / 48) * 48;` — for width=536,870,929 → `aligned_width = 536,870,976`
- `int stride = aligned_width * 8 / 3;` — `536,870,976 × 8 = 4,294,967,808` exceeds `INT_MAX (2,147,483,647)` → signed integer overflow → wraps to `512` → `stride = 170`
- `ff_get_encode_buffer(avctx, pkt, avctx->height * stride, 0)` allocates only ~170 bytes

Then in `v210_enc_8`/`v210_enc_10`:
- `sample_w = 536,870,929 / 6 = 89,478,488`
- `w = sample_w × 6 = 536,870,928`
- `pack_line(y, u, v, dst, w=536,870,928)` writes `(536870928/6)×16 = 1,431,655,808 bytes` into a ~170-byte heap buffer → **heap buffer overflow**
- `dst += sample_w × 16 × sample_factor = 1,431,655,808` — advances `dst` pointer 1.4 GB past the allocation

`ff_get_encode_buffer` guards against `size < 0` (line 110), but with the specific width that wraps stride to a small *positive* value, the guard is bypassed and a dangerously small buffer is returned.

## VULN: Integer Overflow in stride Computation Leading to Heap Buffer Overflow in v210 Encoder
- **漏洞类别**: memory-safety
- **函数**: encode_frame() / v210_enc_8() / v210_enc_10()
- **行号**: v210enc.c:72-78; v210_template.c:29-47
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted media file (e.g., Y4M, rawvideo, or any container supporting large width values)
- **外部触发路径**: ffmpeg -i crafted.y4m -c:v v210 out.mov → avformat_open_input() → avcodec_open2() → encode_frame() → ff_get_encode_buffer() [allocates tiny buffer] → v210_enc_8()/v210_enc_10() → pack_line() [writes gigabytes into tiny buffer → heap overflow]
- **描述**: 在 `encode_frame()`（v210enc.c:73）和 `v210_template.c`（line 30）中，`stride` 的计算为 `int stride = aligned_width * 8 / 3`，均使用有符号 32 位 `int`。当 `avctx->width >= 268,435,441` 时，`aligned_width`（first multiple of 48 ≥ 268,435,488）乘以 8 超过 `INT_MAX (2,147,483,647)`，发生有符号整数溢出（UB，在 x86 上两补数回绕）。例如 width=536,870,929 时 `aligned_width=536,870,976`，`536,870,976×8=4,294,967,808` 回绕为 512，`stride=170`。随后 `ff_get_encode_buffer` 仅分配约 170 字节堆缓冲区（`ff_get_encode_buffer` 仅检查 `size<0`，正溢出值通过检查）。而 `v210_enc_8`/`v210_enc_10` 中 `sample_w=89,478,488`，调用 `pack_line(y,u,v,dst,w=536,870,928)` 将向 dst 写入约 1.4 GB 数据，远超分配的堆缓冲区，造成堆越界写（heap buffer overflow）。
- **触发条件**: 攻击者需构造一个包含视频流的媒体文件（如 Y4M 格式：`YUV4MPEG2 W536870929 H1 F25:1 Ip A1:1 C420` 头），使 `avctx->width` 恰好满足 `aligned_width × 8` 对 `INT_MAX` 的正向溢出，例如 width=536,870,929。用户/服务将该文件通过 `ffmpeg -i crafted.y4m -c:v v210 out.mov` 编码时触发。
- **安全影响**: 堆溢出可覆盖紧随分配缓冲区之后的堆元数据及相邻对象，在能控制溢出内容的条件下（`y`/`u`/`v` 平面像素来自输入文件）可能实现任意堆写，最坏情况导致**远程代码执行（RCE）**；即使无法精确控制写内容，也可造成进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
