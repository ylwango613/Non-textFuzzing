The exploit math is confirmed. Here is the complete audit result:

## VULN: Integer overflow in cvtRaster() output-buffer size → heap buffer overflow
- **漏洞类别**: memory-safety
- **函数**: cvtRaster()
- **行号**: 250-264
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted TIFF file
- **外部触发路径**: rgb2ycbcr main() → tiffcvt() → cvtRaster() → _TIFFmalloc(cc=6) + cvtStrip() [heap OOB write ~6 GB into 6-byte buffer]
- **描述**: 在 `cvtRaster()`（第 250–257 行）中，输出缓冲区大小通过以下公式计算：`cc = rnrows*rwidth + 2*((rnrows*rwidth)/(horizSubSampling*vertSubSampling))`，其中 `rnrows` 和 `rwidth` 均为 `uint32_t`，乘法运算在 32 位无符号域内执行。当 TIFF 文件中 `IMAGEWIDTH = 0x80000001`（2147483649）、`IMAGELENGTH = 1` 时：`rwidth = roundup(0x80000001, 2) = 0x80000002`，`rnrows = 2`，两者之积 `2 × 0x80000002 = 0x100000004` 发生 uint32 溢出，截断为 `4`，最终 `cc = 6`。因此 `_TIFFmalloc(6)` 仅分配 6 字节堆缓冲区（`tsize_t` 为 `int32`，不影响此处结果）。随后 `cvtStrip(buf, raster, 1, 0x80000001)` 被调用，内层循环执行约 10^9 次、每次写 6 字节，共写入约 6.4 GB 数据到该 6 字节缓冲区，造成严重的堆越界写。前置的像素计数溢出检查（第 289 行）仅对 `width×height` 乘积进行保护，对输出缓冲区的独立 `rnrows×rwidth` 乘法没有任何防护。此外，若 `cc` 因不同的宽度参数导致溢出为 0，`_TIFFmalloc(0)` 可能返回 NULL，随后 `cvtStrip(NULL, ...)` 直接触发空指针解引用崩溃（DoS）。
- **触发条件**: 构造一个 TIFF 文件，将 IFD 中的 `TIFFTAG_IMAGEWIDTH`（tag 0x0100）设置为任意满足 `rwidth × rnrows ≥ 2^32` 的值（例如 `0x80000001 = 2147483649`），`TIFFTAG_IMAGELENGTH`（tag 0x0101）设为 `1`；图像数据内容可用高效压缩格式（LZW/PackBits）编码为全零单行以最小化文件体积。目标系统需具备足够的虚拟地址空间（64 位系统默认满足）以完成约 8 GB raster 的 malloc 调用（Linux 默认开启 overcommit，malloc 通常成功）。
- **安全影响**: 攻击者可通过精心构造的 TIFF 文件触发约 6.4 GB 数据写入 6 字节堆缓冲区，在堆上造成大范围内存破坏，最坏情况下可实现任意代码执行（RCE）；在内存不足场景下可可靠触发空指针解引用或 OOM，导致拒绝服务（DoS/Crash）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
