All the context I need is now clear. Here is the complete analysis:

**Overflow math verification for w=16384, h=32769, `AV_PIX_FMT_RGBA64BE`:**
- `n = 16384 * 8 = 131072` (fits in `int32`, no overflow)
- `n * h = 131072 * 32769 = 2^32 + 2^17 = 4,295,098,368` — overflows `int32` to `131072` (positive!)
- `131072 + header_size(~80)` = **131152 bytes allocated** via `ff_get_encode_buffer`
- The `int64_t` guard in `ff_get_encode_buffer` (`size < 0 || size > INT_MAX - padding`) passes because the overflowed value is small and positive
- Loop then runs 32769 iterations of `memcpy(bytestream, ptr, 131072)` → **~4.3 GB written into 131152-byte heap buffer**

The only dimension guard in `ff_encode_preinit` (encode.c:772) is `<= 0` — no upper bound. PAM encoder has no `init` callback. `av_assert1` is `((void)0)` in release builds. The vulnerability is unguarded end-to-end.

## VULN: PAM encoder integer overflow in n*h leading to heap buffer overflow
- **漏洞类别**: memory-safety
- **函数**: pam_encode_frame()
- **行号**: 88-102 (n computation at line 88, overflow site at line 102)
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted media file (e.g., TIFF/PNG/raw with large dimensions)
- **外部触发路径**: `ffmpeg -i malicious.tiff output.pam` → `avformat_open_input()` → decoder (e.g., tiff/png decoder outputs AVFrame w=16384 h=32769 AV_PIX_FMT_RGBA64BE) → `avcodec_send_frame()` → `ff_encode_simple_receive_packet()` → `pam_encode_frame()`
- **描述**: 在 `pam_encode_frame` 中，第88行对 `AV_PIX_FMT_RGBA64BE` 格式计算 `n = w * 8`（int 乘法，w=16384 时 n=131072，无溢出）。第102行 `ff_get_encode_buffer(avctx, pkt, n*h + header_size, 0)` 中，`n*h` 是 `int×int` 乘法，不做溢出检查。当 w=16384、h=32769 时，`131072 * 32769 = 4,295,098,368`，超过 INT_MAX，按 32 位有符号整数回绕为 `131072`（正数）。该值通过隐式转换变为 `int64_t` 后，`ff_get_encode_buffer` 内部的 `size < 0` 检查无法拦截，最终仅分配约 131152 字节。随后第120-124行的循环对每一行调用 `memcpy(bytestream, ptr, n)`，共 32769 行，向 131152 字节缓冲区写入约 4.3 GB 数据，造成堆溢出。
- **触发条件**: 攻击者构造一个宽度=16384、高度=32769（或满足 `w*8*h ≡ k mod 2³²`，且 `k < n` 的任意组合）的高位深（16位/通道）媒体文件（TIFF、PNG 16bpc、EXR 或原始视频流均可）。执行 `ffmpeg -i attacker.tiff out.pam` 触发漏洞。
- **安全影响**: 攻击者完全控制堆溢出的写入内容（来自解码后帧数据）和写入偏移，可覆盖相邻堆块的元数据或函数指针，在最坏情况下实现**任意代码执行（RCE）**；最低限度导致进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
