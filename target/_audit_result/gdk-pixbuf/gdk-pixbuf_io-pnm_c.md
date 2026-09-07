**Analysis complete.** Line 186's inner loop evaluates `*inptr` before `inptr < inend`, causing a 1-byte OOB read when a comment runs to the exact end of the 4096-byte buffer. On a little-endian 64-bit system, `inbuf->buffer[4096]` is the LSB of `inbuf->byte` (the next struct field). If that LSB happens to be `0x0A` (`'\n'`), the loop incorrectly exits as if it found a newline, then the outer loop increments `inptr` to `inend + 1`, and line 202 computes `inbuf->nbytes = (guint)(inend - (inend+1))` → **UINT_MAX**. The subsequent iteration of the outer `while(TRUE)` loop in the loader then calls `memmove(inbuf->buffer, inbuf->byte, UINT_MAX)` — copying ~4 GB, which crashes the process.

## VULN: pnm_skip_whitespace off-by-one OOB read → integer underflow → heap crash

- **漏洞类别**: memory-safety
- **函数**: pnm_skip_whitespace()
- **行号**: 186-202
- **CWE**: CWE-125 (Out-of-bounds Read) → CWE-191 (Integer Underflow) → CWE-119 (Improper Restriction of Operations within the Bounds of a Memory Buffer)
- **CVSS v3.1**: 6.5 (AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted PNM image file (PBM/PGM/PPM)
- **外部触发路径**: `gdk_pixbuf__pnm_image_load` / `gdk_pixbuf__pnm_image_load_increment` → `pnm_read_header` → `pnm_skip_whitespace` (during whitespace skip before or between header values)
- **描述**: 在 `pnm_skip_whitespace()` 的内层循环 `for ( ; *inptr != '\n' && inptr < inend; inptr++)` 中，条件求值顺序错误：`*inptr` 在 `inptr < inend` 之前被求值。当包含 `#comment` 的输入恰好填满 4096 字节缓冲区（`inbuf->nbytes == PNM_BUF_SIZE`，`inend = inbuf->buffer + 4096`）且缓冲区末尾无换行符时，循环最后一次迭代将读取 `*inend = inbuf->buffer[4096]`（越界 1 字节），该地址实际上是 `PnmIOBuffer.byte` 指针字段的最低字节（小端 64 位系统）。若该字节恰好为 `'\n'`（0x0A），内层循环错误地认为找到了行尾并退出；随后外层循环的 `inptr++` 使 `inptr = inend + 1`，外层循环条件 `inptr < inend` 失败退出，执行到第 201-202 行：`inbuf->byte = inend + 1`（已超出缓冲区），`inbuf->nbytes = (guint)(inend - (inend+1))` 计算为无符号下溢，结果为 **UINT_MAX（≈4.3 亿）**。调用方以 `PNM_SUSPEND` 继续循环，下一轮执行 `memmove(inbuf->buffer, inbuf->byte, inbuf->nbytes)` 即 `memmove(buffer, buffer+4097, 4294967295)`，触发跨越整个进程地址空间的越界读写，必然引发崩溃。
- **触发条件**: 构造一个 PNM 文件，使其以 `#comment` 内容恰好完整填充 4096 字节的输入缓冲区且不含换行符结尾；同时需要 `inbuf->buffer[4096]`（即 `inbuf->byte` 指针的 LSB）等于 `0x0A`。在非 ASLR 环境或可通过堆喷影响 `PnmLoaderContext` 分配地址的场景下可确定性触发；随机情况下概率约为 1/256。
- **安全影响**: 进程崩溃（拒绝服务）。在极端情况下，若进程未立即 SIGSEGV 而执行了部分 memmove 写操作，可能导致堆内存大规模损坏，理论上可升级为远程代码执行，但实际利用难度高。

<!-- AUDIT_PROMPT_VERSION: 1 -->
