Based on my thorough analysis of `ShadingImage.h` and the full `ShadingImage.cc` implementation (1337 lines, read in three passes), I found one real memory safety vulnerability.

## VULN: Integer Overflow in generateGouraudTriangleBitmap Alpha-Buffer memset
- **漏洞类别**: memory-safety
- **函数**: ShadingImage::generateGouraudTriangleBitmap()
- **行号**: 778 (ShadingImage.cc)
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-787 (Out-of-bounds Write)
- **CVSS v3.1**: 6.3 (AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted PDF file with type-4 or type-5 shading (Gouraud triangle shading)
- **外部触发路径**: xpdf viewer/pdftohtml opens crafted PDF → `Gfx::doShadingFill()` → `Gfx::doShFill()` → `SplashOutputDev::shadedFill()` (SplashOutputDev.cc:2231) → `ShadingImage::generateBitmap()` → `ShadingImage::generateGouraudTriangleBitmap()` → `SplashBitmap` constructor allocates alpha buffer of `height × width` bytes → `memset(bitmap->getAlphaPtr(), 0, bitmap->getHeight() * bitmap->getWidth())` with overflowed int argument → heap OOB write
- **描述**: 在 `generateGouraudTriangleBitmap` 函数第 778 行，调用 `memset(bitmap->getAlphaPtr(), 0, bitmap->getHeight() * bitmap->getWidth())`。其中 `getHeight()` 和 `getWidth()` 均返回 `int` 类型。当 `bitmapHeight * bitmapWidth` 超过 `INT_MAX`（2,147,483,647）时，两个 `int` 相乘发生有符号整数溢出（C++ UB），结果为负数（例如 `46342 × 46342 = 2,147,580,964` 溢出为约 `-2,147,386,332`）。该负数被隐式转换为 `size_t` 传入 `memset`（在 64 位系统上变为约 18 EB），导致 `memset` 从 alpha 缓冲区起始向外写出大量零字节，形成堆越界写入，立即触发段错误崩溃。第 777 行的数据缓冲区 `memset` 因 `SplashBitmapRowSize` 在 64 位系统上为 `long long`（`int × long long = long long`），不受此问题影响；alpha 行的乘法 `int × int = int` 则没有对应保护。
- **触发条件**: 攻击者需构造一个 PDF，其 Gouraud 三角形渐变填充（shading type 4 或 type 5）通过超大 CTM 缩放矩阵使设备空间剪切区域总像素数超过 `INT_MAX`（即 `bitmapWidth × bitmapHeight > 2^31`）。例如，`bitmapWidth = 2`、`bitmapHeight = 1,073,741,825` 像素时溢出，此时 alpha 缓冲区本身需要 ~2 GB，数据缓冲区需要 ~6 GB（RGB8），目标系统需有约 4–9 GB 空闲内存才能在 `memset` 前完成分配（若分配失败则 `gmallocn64` 调用 `gMemError` 直接 abort，不触发此路径）。
- **安全影响**: 导致 xpdf 图形查看器或 pdftohtml 崩溃（DoS）。`memset` 写入天文数字字节的零值，碰到未映射内存页后立即触发 SIGSEGV。在极端有利的堆布局下（alpha 缓冲区恰好毗邻其他堆对象且有足够可写映射），大量零字节覆盖后续堆数据，存在堆元数据破坏的理论可能，但实际利用为 RCE 的概率极低；最现实的影响为可靠的进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
