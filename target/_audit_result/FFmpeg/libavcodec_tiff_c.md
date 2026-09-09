I have now done a thorough multi-pass analysis of the full file. Here is my final conclusion.

## VULN: Heap Buffer Overflow via Integer Overflow in five_planes Allocation for PHOTOMETRIC_SEPARATED TIFF
- **漏洞类别**: memory-safety
- **函数**: decode_frame()
- **行号**: 2215-2219
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 8.1 (AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted TIFF media file
- **外部触发路径**: `ffmpeg -i <crafted.tiff> -f null -` → `avformat_open_input()` → `tiff_decode()` → `decode_frame()` → signed integer overflow at `stride = stride * 5 / 4` and `av_malloc(stride * s->height)` → heap underallocation → `tiff_unpack_strip()` → `memcpy(five_planes, src, width)` → heap OOB write
- **描述**: 在 `decode_frame()` 处理 PHOTOMETRIC_SEPARATED + CMYK+Alpha（bpp=40, bppcount=5, pix_fmt=AV_PIX_FMT_RGBA）格式的 TIFF 图像时，代码在第 2217 行执行 `stride = stride * 5 / 4`，其中 `stride`（= `p->linesize[0]`，对于宽度约 107374182 像素的图像，经 16 字节对齐后约为 429496736）× 5 = 2147483680，超出 32 位有符号整数上限（2147483647），发生有符号整数溢出（UB，在 x86-64 上 GCC 典型行为为截断到 32），结果变为 32，整除 4 后 stride = 8。随后第 2219 行 `av_malloc(stride * s->height)` = `av_malloc(8 * 4)` = `av_malloc(32)`，仅分配 32 字节给 `five_planes`。但在后续 `tiff_unpack_strip()` 调用中，实际每行写入 `width = (s->width * 40 + 7) / 8 = 536870910` 字节（约 512MB）数据到该 32 字节缓冲区（`memcpy(dst=five_planes, src, width=536870910)`），造成约 512MB 的堆越界写入，彻底破坏堆布局。
- **触发条件**: 攻击者构造一个 CMYK+Alpha TIFF 文件，设置以下字段：PhotometricInterpretation=5（PHOTOMETRIC_SEPARATED）、SamplesPerPixel=5（bppcount=5）、BitsPerSample=8（bpp=40）、ImageWidth ≈ 107374182（使经对齐后的 linesize×5 恰好溢出 int32）、ImageLength=4（高度=4 行）。可使用 DEFLATE 压缩（构造极小的 zip-bomb 式 strip）以减小 PoC 文件体积。系统需有约 1.6GB 可用内存供帧分配成功，触发后即发生约 512MB 堆溢出写入。
- **安全影响**: 攻击者通过触发约 512MB 的堆越界写入，必然导致目标进程崩溃（DoS）；结合堆喷射等技术，在特定内存布局条件下存在通过堆破坏实现远程代码执行（RCE）的潜力。

<!-- AUDIT_PROMPT_VERSION: 1 -->
