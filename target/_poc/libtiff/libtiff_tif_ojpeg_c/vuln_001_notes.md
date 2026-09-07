# vuln_001: Integer overflow in OJPEGWriteHeaderInfo → heap buffer overflow

## Status: SKIPPED

## 跳过原因

该漏洞无法通过 tiffsplit 命令行触发，原因有两个独立的阻断：

### 阻断 1：TIFFScanlineSize 检测溢出，TIFFOpen 返回 NULL

触发 OJPEGWriteHeaderInfo 整数溢出需要 ImageWidth = 0x20000001（约 5.4 亿像素）。
TIFFReadDirectory 内部调用 TIFFScanlineSize，计算过程中 `multiply(0x60000003, 8)` 发生 uint32
溢出，返回 0。libtiff 在 tif_dirread.c:801 检测到零字节扫描线大小并拒绝打开文件。
tiffsplit 的 TIFFOpen 返回 NULL，直接退出，不会进入解码路径。

### 阻断 2：tiffsplit 只调用 TIFFReadRawStrip，不走 OJPEG 解码路径

tiffsplit 内部的 cpStrips() 仅调用 TIFFReadRawStrip()。对于 OJPEG 压缩，
tif_ojpeg.c:448 在 OJPEGSetupDecode 中设置了 TIFF_NOREADRAW 标志，导致
TIFFReadRawStrip 立即返回 -1。OJPEGPreDecode（包含 OJPEGWriteHeaderInfo 及
第 1142 行的整数溢出）仅通过 TIFFReadEncodedStrip / TIFFReadScanline 可达，
而 tiffsplit 不调用这两个 API。

## 漏洞描述（静态分析确认）

- 位置：tif_ojpeg.c 第 1142–1144 行，OJPEGWriteHeaderInfo()
- 溢出：`ylinelen = 0x20000008`，`ylines = 8`
  - `ylinelen × ylines = 0x100000040` → uint32 截断为 0x40 = 64
  - `ycbcrbuflen = 64 + 64 + 64 = 192` 字节
- 行指针越界：`ybuf + 1 × 0x20000008 = ybuf + 536 MB`（越界 heap 读写）
- 实际触发需要使用 tiff2rgba、tiff2pdf、TIFFRGBAImageGet 等调用 TIFFReadEncodedStrip/TIFFReadScanline 的工具。
