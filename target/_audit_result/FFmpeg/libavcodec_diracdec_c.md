## VULN: Integer Overflow in thread_buf Index → OOB Heap Write in decode_hq_slice_row
- **漏洞类别**: memory-safety
- **函数**: decode_hq_slice_row()
- **行号**: 918-926 (核心在923行；根因在180行 int thread_buf_size 及 962行赋值)
- **CWE**: CWE-190 (Integer Overflow or Wraparound)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted VC-2 / Dirac media file
- **外部触发路径**: ffmpeg -i crafted.vc2 -f null - → dirac_decode_frame() → decode_lowdelay() → avctx->execute2(decode_hq_slice_row) → decode_hq_slice_row() → `&s->thread_buf[s->thread_buf_size * threadnr]` 触发整数溢出 → OOB heap write
- **描述**: `DiracContext.thread_buf_size` 声明为 `int`（第180行），在 `decode_lowdelay()` 第962行以 `int64_t coef_buf_size` 赋值（对合法尺寸图像，该值不截断）。`decode_hq_slice_row()` 第923行执行 `&s->thread_buf[s->thread_buf_size * threadnr]`，其中 `s->thread_buf_size`（int）× `threadnr`（int）为有符号 int 乘法。当 HQ picture 为 10-bit（pshift=1）、图像尺寸约 16600×16600 像素（符合 max_pixels=INT_MAX 限制）、num_x=num_y=1（单切片覆盖全帧）时，`thread_buf_size ≈ 1,103,303,200`。在 threadnr=2（第3个线程，需 ≥3 CPU 线程）时，乘积 2,206,606,400 超过 INT_MAX=2,147,483,647，触发有符号整数溢出（C UB），在 x86 上通常回绕为约 -2,088,360,896。最终 `thread_buf` 指针被移至堆分配区域起始位置前约 2GB 处，随后 `decode_hq_slice()` 将系数数据写入该错误地址，造成堆越界写。
- **触发条件**: 攻击者构造一个 VC-2 HQ picture 码流，设置：(1) bit_depth > 8（10-bit，pshift=1）；(2) 图像尺寸 ≥ 约 16584×16584（使 thread_buf_size > INT_MAX/2）；(3) num_x=1, num_y=1（整帧单切片，最大化 thread_buf_size）；(4) 目标系统需有 ≥3 个解码线程（默认 FFmpeg 按 CPU 核数设置线程数，现代多核机器均满足）；(5) 系统需有足够内存完成 `av_realloc_f(ptr, thread_count, ~1.1GB)` 分配（≥3.3GB 连续内存）。
- **安全影响**: 最坏情况下：通过堆布局控制，将系数数据写入攻击者可控的堆对象，实现远程代码执行（RCE）。在无法精确控制堆布局时，触发进程崩溃（DoS）。漏洞在 ffmpeg、ffplay 等所有使用 Dirac/VC-2 解码器且在多核机器上运行的应用中均可触发。

<!-- AUDIT_PROMPT_VERSION: 1 -->
