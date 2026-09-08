All analysis complete. The two distinct integer overflow paths are confirmed:

1. `need_align * avctx->height` (int×int) overflow at line 630 — bypasses the size safety check; realistic trigger with width=2048, height=65536, bits=32.
2. `4 * avctx->width * dpx->components` overflow in `dpx->stride` (line 522) for extreme widths — corrupts the stride value to negative, also bypassing the size check via the same mechanism.

Both produce the same consequence: `unpack_frame` reads gigabytes past the end of the (tiny) packet buffer.

## VULN: Integer overflow in size check bypasses bounds guard → heap OOB read in unpack_frame
- **漏洞类别**: memory-safety
- **函数**: decode_frame()
- **行号**: 629-644 (integer overflow in size check), 127-265 (OOB read in unpack_frame)
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 8.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted DPX image file
- **外部触发路径**: `ffmpeg -i crafted.dpx -f null -` → `avcodec_send_packet()` → `decode_frame()` → integer overflow at line 630 bypasses size check → `unpack_frame()` OOB heap read
- **描述**: 在 `decode_frame()` 第 630 行，安全边界检查的表达式 `dpx->need_align * avctx->height` 是 `int × int` 乘法，在两个操作数的乘积超过 `INT_MAX` 时产生有符号整数溢出（UB，实际以 wrap-around 表现）。结果（如 `-2147483648`）随后才隐式提升为 `int64_t` 进行后续比较，但此时损害已经形成：负数加上合法的 `offset` 值仍然远小于 `avpkt->size`，致使整个 `if` 条件为 `FALSE`，从而跳过了外层安全守卫；内层冗余检查（第 633 行）仅在外层 `if` 为 `TRUE` 时才执行，因此也一并被绕过。代码随即落入 `else` 分支，设置了"正确"的 `stride` 和 `need_align` 后直接调用 `unpack_frame()`。`unpack_frame()` 内部的循环（如第 215–235 行的 32-bit 浮点多平面循环）以 `buf = avpkt->data + offset` 为起点，按像素逐步前进，总共尝试读取 `width × height × bytes_per_pixel`（示例：2048×65536×16 ≈ 2 GB）字节，而实际 packet 仅有数 KB，从而导致堆越界读取。第二条独立的整数溢出路径存在于第 522 行的 `dpx->stride = 4 * avctx->width * dpx->components` 计算中：当 `avctx->width` 接近 `av_image_check_size2` 允许的上限（约 268M）且 `dpx->components=4` 时，`4 × width × 4` 的结果（约 4.3 × 10⁹）超出 int32 上限，产生负值 stride；该负值同样使第 630 行的边界检查失效，并可能在后续像素读取循环中造成额外的内存访问异常。
- **触发条件**: 攻击者需构造一个 DPX 文件：将 DPX 头部字段 width 设为 2048、height 设为 65536（或任意满足 `aligned_stride × height > INT_MAX` 的值）、`bits_per_raw_sample` 设为 32（0x20）、descriptor 设为 51（RGBA）；同时将 data offset 字段设置为一个合法的较小值（如 2048），并将实际文件内容截断为仅含头部（约 2–4 KB），不提供任何真实像素数据。
- **安全影响**: 最坏情况下：(1) 进程必然崩溃（SIGSEGV），可被攻击者用于远程 DoS；(2) 在 heap layout 可预测或有信息反馈的上下文（如服务端转码服务），越界读取的字节被写入 AVFrame 数据平面，可能泄露相邻堆内存中的敏感数据（密钥、token、用户数据），构成信息泄露。

## VULN: Integer overflow in dpx->stride computation produces negative src_linesize for av_image_copy_plane
- **漏洞类别**: memory-safety
- **函数**: decode_frame() / unpack_frame()
- **行号**: 522 (stride overflow), 629-644 (check bypass), 211-213 (av_image_copy_plane OOB)
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.1 (AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted DPX image file
- **外部触发路径**: `ffmpeg -i crafted.dpx -f null -` → `decode_frame()` → 第 522 行 `dpx->stride = 4 * avctx->width * dpx->components` 溢出为负值 → 第 630 行大小检查被负值绕过 → `unpack_frame()` → `av_image_copy_plane()` 以负 `src_linesize` 调用 → 向后读取堆内存
- **描述**: 对于 `bits_per_raw_sample == 32` 的路径（第 522 行）：当 `avctx->width` 较大（如 268435327，位于 `av_image_check_size2` 允许范围内）且 `dpx->components == 4` 时，表达式 `4 * avctx->width * dpx->components`（纯 `int` 运算，值约 4,294,965,232）超出 `INT_MAX`，产生负 stride（如 `-2064`）。`FFALIGN(negative, 4)` 仍返回负值，`need_align * height` 随即产生负数结果，使第 630 行的 `if` 条件为 `FALSE` 而跳过安全守卫。最终 `dpx->stride` 以负值（`-2064`）传入 `av_image_copy_plane()` 作为 `src_linesize`：在 `height > 1` 的情形下，第二行及后续行的源指针（`src += src_linesize`）将在首次 `memcpy` 后向低地址移动，读取位于原 packet 数据之前的堆内存，构成堆越界读取。此外，`bytewidth = elements * avctx->width * 4` 在 `elements`（解包后可达 8）与大 `width` 的组合下也可独立溢出，导致 `memcpy` 的 `size_t` 参数接收到极大的无符号值，造成即时崩溃（DoS）。
- **触发条件**: 构造 DPX 文件：descriptor=51（RGBA），`bits_per_raw_sample=32`，width=268435327（接近 `av_image_check_size2` 允许上限），height=2；实际像素数据区为空或极小。
- **安全影响**: (1) 必然崩溃（DoS）；(2) height > 1 时，`av_image_copy_plane` 以负 `src_linesize` 向前（低地址）读取，可泄露位于 packet 缓冲区之前的堆内存内容（信息泄露）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
