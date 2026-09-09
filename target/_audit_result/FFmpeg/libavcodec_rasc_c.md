Confirmed. Now I have a precise concrete example. With `w=32100, h=44600` (both within PAL8 dimension limits), `3*w*h mod 2^32 = 12704`, cursor buffer is only 12768 bytes, but `draw_cursor` indexes up to 4,294,979,999. This is ~4 GB past the buffer — a massive heap OOB read.

## VULN: decode_mous Integer Overflow in `3 * w * h` Bypasses Cursor Size Validation Leading to Heap OOB Read in draw_cursor
- **漏洞类别**: memory-safety
- **函数**: decode_mous() / draw_cursor()
- **行号**: 561–586 (decode_mous), 625–683 (draw_cursor)
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 8.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted RASC media file
- **外部触发路径**: `ffmpeg -i crafted.rasc -f null -` → `avcodec_decode_video2()` → `decode_frame()` → `decode_mous()` [integer overflow, cursor_w/cursor_h set to giant values] → `draw_cursor()` [OOB heap read via s->cursor[3 * cursor_w * ...]]
- **描述**: 在 `decode_mous()`（第 569 行）中，验证逻辑为 `if (uncompressed_size != 3 * w * h)`，其中 `w` 和 `h` 均为 `unsigned` 类型，三者乘积在 unsigned 32-bit 下可以发生环绕（wraparound）。当 `3 * w * h` 的真实数学值超过 `2^32` 时，模运算结果是一个远小于实际所需空间的值。攻击者将文件中的 `uncompressed_size` 字段设置为该环绕值（如 12704），使等值检查通过。随后 `av_fast_padded_malloc` 仅分配约 12768 字节的 cursor 缓冲区，但 `s->cursor_w = w`（32100）和 `s->cursor_h = h`（44600）仍被存储为真实大尺寸。当 `draw_cursor()` 被调用时，像素访问表达式 `s->cursor[3 * s->cursor_w * (s->cursor_h - i - 1) + 3 * j + 0]` 的最大索引达到约 4,294,979,999，远超 12768 字节的缓冲区，造成巨型堆越界读（heap OOB read）。OOB 读取到的 `cr/cg/cb` 值被写入输出帧（s->frame），可能将堆内存内容泄露到解码输出流中。
- **触发条件**: 攻击者需构造一个 RASC 格式的媒体文件（通常封装于 AVI/ASF 容器中）：① 首先发送 FINT/INIT chunk，指定 `fmt=8`（PAL8，bpp=1），并设置大尺寸 `w=32100, h=44600`（均满足 PAL8 的 imgutils 尺寸上限：`(w+1024)*(h+128) < INT_MAX`）；② 发送 MOUS chunk，`w=32100, h=44600`，`uncompressed_size=12704`（即 `3*32100*44600 mod 2^32`）；③ 发送合法压缩的 cursor 数据（zlib 解压后 ≤ delta buffer 大小）；④ 后续帧正常解码触发 `draw_cursor()`。
- **安全影响**: 最坏情况下，OOB 读取堆内存中的任意数据（指针、密钥等）并将其编码到输出帧的像素值中，造成敏感信息泄露（Information Disclosure）。若 OOB 读取触及未映射内存页，程序崩溃（DoS）。在服务端 FFmpeg 视频处理管线中，信息泄露可能被用于后续利用（如 ASLR bypass）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
