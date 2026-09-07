Based on my thorough analysis of `pal2rgb.c` and the related libtiff source (`tif_strip.c`, `tif_unix.c`, `tiffio.h`, `tif_dir.c`, `tif_dirread.c`), here are my confirmed findings:

**Key facts established:**
- `tsize_t` is `int32` (signed 32-bit) — confirmed at `tiffio.h:67`
- `TIFFScanlineSize()` uses a `multiply()` helper (tif_strip.c:52) that detects overflow by computing `uint32 bytes = nmemb * elem_size` and checking `bytes / elem_size != nmemb`; returns 0 on overflow
- `_TIFFmalloc(tsize_t s)` simply calls `malloc((size_t) s)` — no zero-size guard (tif_unix.c:239-242)
- On Linux/glibc, `malloc(0)` returns a unique non-NULL pointer (0 usable bytes); writing to it is heap corruption
- The inner pixel loop at lines 188-191 writes `imagewidth * 3` bytes to `obuf`, which was allocated `TIFFScanlineSize(out)` bytes — with no size validation between these two quantities

---

## VULN: Heap buffer overflow via TIFFScanlineSize integer overflow writing to malloc(0) obuf
- **漏洞类别**: memory-safety
- **函数**: main()
- **行号**: 180-195
- **CWE**: CWE-122 (Heap-Based Buffer Overflow)
- **CVSS v3.1**: 7.8 (AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted TIFF file
- **外部触发路径**: pal2rgb main() → _TIFFmalloc(TIFFScanlineSize(out)) [returns malloc(0) due to overflow] → pixel loop writes imagewidth*3 bytes to 0-size heap block (lines 188-191)
- **描述**: `TIFFScanlineSize(out)` 内部调用 `multiply(tif, scanline, bitspersample, ...)` 计算输出扫描线字节数。当 `imagewidth ≥ 178,956,971` 时（CONTIG 模式，samplesperpixel=3，bitspersample=8），`multiply()` 中 `uint32 bytes = 536,870,913 * 8 = 4,294,967,304` 截断为 `8`，溢出检查触发，`multiply()` 返回 0，`TIFFScanlineSize(out)` 返回 0。随后 `_TIFFmalloc(0)` 在 Linux/glibc 上返回一个合法但无可用字节的非 NULL 指针（heap 上最小对齐块）。pal2rgb.c:181 将其赋给 `obuf` 而不做任何零大小检查。之后在 line 188-191 的像素循环中，代码向 `obuf` 连续写入 `imagewidth * 3`（约 536MB）字节，远超 0 字节分配边界，造成严重的堆缓冲区溢出，破坏 heap 相邻内存块的元数据和内容。
- **触发条件**: 攻击者构造 TIFF 文件：PHOTOMETRIC_PALETTE，bitspersample=8，imagewidth ≥ 178,956,971，imagelength=1（最小化文件大小），COMPRESSION_NONE，在 StripOffsets 指向的位置放置 ≥178,956,971 字节合法调色板索引数据（约 170MB 文件）。以默认参数调用 `pal2rgb crafted.tif out.tif`（无需 `-p` 参数，默认 CONTIG）。系统需有约 170MB 空闲内存使 ibuf 分配成功，obuf 随后以 malloc(0) 完成分配，循环触发堆溢出。
- **安全影响**: 堆内存大量越界写入（每行约 536MB），几乎必然导致进程崩溃（DoS）。在精心控制的堆布局下（heap feng shui），相邻 heap 元数据被覆盖可能导致任意代码执行（RCE）。

## VULN: NULL pointer dereference from unchecked _TIFFmalloc return on ibuf/obuf
- **漏洞类别**: memory-safety
- **函数**: main()
- **行号**: 180-191
- **CWE**: CWE-476 (NULL Pointer Dereference)
- **CVSS v3.1**: 5.5 (AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted TIFF file
- **外部触发路径**: pal2rgb main() → _TIFFmalloc(TIFFScanlineSize(in)) returns NULL → TIFFReadScanline(in, NULL, row, 0) at line 185 → NULL pointer dereference inside library
- **描述**: line 180 的 `ibuf = _TIFFmalloc(TIFFScanlineSize(in))` 和 line 181 的 `obuf = _TIFFmalloc(TIFFScanlineSize(out))` 均无返回值 NULL 检查。当攻击者将 TIFF 的 imagewidth 设置为极大值（如 UINT32_MAX = 4,294,967,295）时，`TIFFScanlineSize(in)` 为 1spp/8bpp 调色板图像返回 `imagewidth` 字节（约 4GB），`_TIFFmalloc(4GB)` 内存分配失败返回 NULL，ibuf 被赋值 NULL。随后 line 185 的 `TIFFReadScanline(in, NULL, row, 0)` 被调用，库内部尝试将解码后的像素数据写入 NULL 地址，触发 NULL 指针解引用，进程立即崩溃。同路径下，在某些 malloc(0) 返回 NULL 的平台（非 glibc）上，obuf=NULL 也会被 line 187 的 `pp = obuf; *pp++ = ...` 触发。攻击者无需提供实际图像数据，仅修改 TIFF IFD 中的 imagewidth 字段即可触发。
- **触发条件**: 攻击者构造 TIFF 文件，设置 PHOTOMETRIC_PALETTE，bitspersample=8，imagewidth = 0xFFFFFFFF（或任意足够大导致 malloc 失败的值）。TIFF 文件本身可以很小（头部 + IFD，无需提供实际图像数据），因为崩溃发生在分配阶段，早于 TIFFReadScanline 实际读取任何条带数据之前。
- **安全影响**: 进程崩溃（段错误），服务拒绝（DoS）。不可直接利用于代码执行，但在依赖 pal2rgb 的自动化管道中可造成持续性 DoS。

<!-- AUDIT_PROMPT_VERSION: 1 -->
