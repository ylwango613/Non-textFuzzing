全分析完了。以下にまとめます。

---

## VULN: Integer Overflow in dwt_buf Allocation Causing Heap OOB Write
- **漏洞类别**: memory-safety
- **函数**: cfhd_encode_init()
- **行号**: 278-301
- **CWE**: CWE-190 (Integer Overflow or Wraparound)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted media file (transcoded to CFHD format)
- **外部触发路径**: ffmpeg -i crafted.avi -c:v cfhd output.cfhd -> avcodec_open2() -> cfhd_encode_init() -> av_calloc(h8 * 8 * w8 * 8, ...)
- **描述**: 在 `cfhd_encode_init()` 的第 278-288 行，局部变量 `w8`, `h8`, `w4`, `h4`, `w2`, `h2` 均为 `int` 类型。计算 `h8 * 8 * w8 * 8` 时全部以有符号 32 位整数进行。当 width=65536、height=65536（均为 16 的整数倍，满足第 265 行的唯一约束）时：`h8=8192`, `w8=8256`，中间结果 `65536 * 8256 * 8 = 4,328,521,728`，超过 INT_MAX（2,147,483,647），发生有符号整数溢出，wraps to `33,554,432`。`av_calloc(33554432, sizeof(int16_t))` 仅分配约 64 MB，而实际需要约 8 GB。随后第 293-301 行计算 subband 指针时使用同样的大宽高，如 `subband[8] = dwt_buf + 1 * w2 * h2`（= `dwt_buf + 1,082,130,432`），其偏移量远超过 dwt_buf 的实际大小（33,554,432 元素），造成指针越界。在 `cfhd_encode_frame()` 中通过这些 subband 指针进行写操作，触发大规模堆越界写，损坏堆元数据。
- **触发条件**: 攻击者构造包含视频流的媒体文件（如 AVI/MKV），声明 width=65536（或其他满足 `h * (w+512) ≈ k * 2^32` 使溢出后取值较小的组合，且 width 为 16 的整数倍），height=65536 或同量级大值。用户使用 `ffmpeg -i malicious.avi -c:v cfhd output.cfhd` 进行转码时触发，编码器 init 时完成欠分配，编码第一帧时发生 OOB 写。
- **安全影响**: 堆越界写，可覆盖 libc 堆元数据或相邻 chunk，在最坏情况下可实现远程代码执行（RCE）。在流媒体服务器场景中，远程攻击者提供恶意文件即可触发，无需本地访问权限。

## VULN: Integer Overflow in s->alpha Allocation Causing Heap OOB Write
- **漏洞类别**: memory-safety
- **函数**: cfhd_encode_init()
- **行号**: 370-375
- **CWE**: CWE-190 (Integer Overflow or Wraparound)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted media file (GBRAP12 transcoded to CFHD format)
- **外部触发路径**: ffmpeg -i crafted_gbrap.avi -pix_fmt gbrap12 -c:v cfhd output.cfhd -> cfhd_encode_init() -> av_calloc(avctx->width * avctx->height, ...) -> cfhd_encode_frame() -> process_alpha()
- **描述**: 第 370 行判断 `s->planes != 4` 时提前返回，仅 `AV_PIX_FMT_GBRAP12` 格式（4 planes）会执行第 373 行的 alpha 缓冲区分配：`s->alpha = av_calloc(avctx->width * avctx->height, sizeof(*s->alpha))`。`avctx->width * avctx->height` 以 `int * int` 计算。当 width=46336、height=46352（均为 16 的整数倍，满足宽度约束）时：`46336 * 46352 = 2,147,766,272` > INT_MAX，有符号溢出到 `282,624`。`av_calloc(282624, 2)` 仅分配约 565 KB 的空间。随后在 `cfhd_encode_frame()` 第 452 行调用 `process_alpha(input, avctx->width, avctx->height, in_stride, s->alpha)`，该函数以完整的 width×height（约 21 亿个元素）迭代向 `s->alpha` 写入，造成约 4.3 GB 的堆越界写，大规模损坏堆结构。
- **触发条件**: 攻击者构造能产生 GBRAP12 格式（带 alpha 通道的 12 位 GBR）像素数据的媒体文件，并声明宽高约为 46336×46352 或其他使 `w*h` 溢出后取小正值的组合（均须为 16 的倍数）。用户将该文件转码为 CFHD 格式时触发。
- **安全影响**: 大规模堆越界写（覆盖范围 4+ GB），必然造成堆损坏。在受控条件下（如堆喷射）可利用为任意代码执行（RCE）；在普通条件下至少造成进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
