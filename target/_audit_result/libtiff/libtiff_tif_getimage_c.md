Now I have all the context needed. Let me confirm the key inconsistency between the contig vs. separate paths:

**Batch analysis findings summary:**

- **Lines 682-688 (`gtTileSeparate`)**: Uses `TIFFSafeMultiply` and checks `if (bufsize == 0) { return 0; }` ← **protected**
- **Lines 894-898 (`gtStripSeparate`)**: Same safe check ← **protected**  
- **Line 582 (`gtTileContig`)**: `_TIFFmalloc(TIFFTileSize(tif))` — **no zero check** ← **VULNERABLE**
- **Line 808 (`gtStripContig`)**: `_TIFFmalloc(TIFFStripSize(tif))` — **no zero check** ← **VULNERABLE**

When `TIFFTileSize`/`TIFFStripSize` return 0 (due to `multiply()` uint32 overflow guard at tif_strip.c:56-59), `malloc(0)` on Linux/glibc returns a valid non-NULL pointer, bypassing the `if (buf == 0)` guard. Subsequent `put` routines then read `tw × nrow × bpp` bytes from this 0-byte allocation — a heap out-of-bounds read. The `TIFFReadTile`/`TIFFReadEncodedStrip` calls are capped at `tif_tilesize=0` bytes written, so the decode itself doesn't overflow the buffer. But the pixel-processing `put` routines unconditionally read from `buf + pos` based on the image dimensions, causing the OOB read.

## VULN: gtTileContig heap OOB read via TIFFTileSize overflow and malloc(0)
- **漏洞类别**: memory-safety
- **函数**: gtTileContig()
- **行号**: 582-629
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.1 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted TIFF file
- **外部触发路径**: tiffsplit main() -> TIFFOpen() -> TIFFReadRGBAImage() -> TIFFRGBAImageOK() -> TIFFRGBAImageBegin() -> PickContigCase() -> [img->get = gtTileContig] -> TIFFRGBAImageGet() -> gtTileContig()
- **描述**: 在 `gtTileContig()` 中，`buf = (unsigned char*) _TIFFmalloc(TIFFTileSize(tif))` 调用时未检查 `TIFFTileSize()` 的返回值是否为 0。当 TIFF 文件中的 TileWidth×TileLength（或 ×SamplesPerPixel×BitsPerSample/8）乘积超过 UINT32_MAX 时，tif_tile.c 中的 `multiply()` 溢出检测机制将 `tilesize` 置零，`TIFFTileSize` 返回 0。此时 `_TIFFmalloc(0)` 在 glibc/Linux 上返回一个有效的非 NULL 指针（指向最小堆块），`if (buf == 0)` 守卫被绕过。随后 `TIFFReadTile()` 内部以 `size = tif->tif_tilesize = 0` 限制解码写入（不写入数据），但紧接着的 `put` 回调（如 `putRGBcontig8bittile`、`put8bitcmaptile` 等）以真实的瓦片宽高 `tw × nrow × samplesperpixel` 字节为步长从 `buf + pos` 读取像素数据，导致堆越界读取（可读取 tw×th×spp 字节的堆区域内容）。与此形成对比的是 `gtTileSeparate`（line 683–686）使用了 `TIFFSafeMultiply` + 零值检查加以防护，而 `gtTileContig` 缺失同等保护。
- **触发条件**: 攻击者构造一个 tiled TIFF 文件，将 PLANARCONFIG 设置为 PLANARCONFIG_CONTIG，TileWidth 和 TileLength 的乘积（×spp×bps/8）超过 UINT32_MAX（例如 TileWidth=65536，TileLength=65536，spp=1，bps=8 时乘积 = 2^32，在 32 位 `multiply()` 中溢出为 0）；同时使 image height/width 非零以使 put 循环执行。
- **安全影响**: 攻击者可通过精心构造的 TIFF 导致 libtiff 堆越界读取，读取到的堆元数据或其他敏感数据被写入调用方提供的 raster 缓冲区，造成堆内存信息泄露（C:H）；若读取到未映射页，触发 SIGSEGV 崩溃（A:H），可用于 DoS 攻击。

## VULN: gtStripContig heap OOB read via TIFFStripSize overflow and malloc(0)
- **漏洞类别**: memory-safety
- **函数**: gtStripContig()
- **行号**: 808-846
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.1 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted TIFF file
- **外部触发路径**: tiffsplit main() -> TIFFOpen() -> TIFFReadRGBAImage() -> TIFFRGBAImageOK() -> TIFFRGBAImageBegin() -> PickContigCase() -> [img->get = gtStripContig] -> TIFFRGBAImageGet() -> gtStripContig()
- **描述**: 在 `gtStripContig()` 中，`buf = (unsigned char*) _TIFFmalloc(TIFFStripSize(tif))` 调用时未检查 `TIFFStripSize()` 的返回值是否为 0。`TIFFStripSize` 通过 `TIFFVStripSize` → `multiply(tif, nrows, TIFFScanlineSize(tif), ...)` 计算，当 `rowsperstrip × scanlinesize`（即 `rowsperstrip × imagewidth × spp × bps/8`）超过 UINT32_MAX 时，`multiply()` 将结果置零，`TIFFStripSize` 返回 0。`_TIFFmalloc(0)` 在 glibc 上返回非 NULL 指针，绕过 `if (buf == 0)` 检查。`_TIFFmemset(buf, 0, TIFFStripSize(tif))` 以 0 字节为参数（无写入）。`TIFFReadEncodedStrip` 内部将 size 限制为 `TIFFVStripSize = 0` 后调用解码器写入 0 字节。随后 `put` 回调以真实的 `w × nrow` 像素数量从 `buf + pos` 连续读取，造成对 0 字节分配的堆越界读取。与 `gtStripSeparate`（line 894-898）使用 `TIFFSafeMultiply` + 零值检查防护不同，`gtStripContig` 缺失同等保护。
- **触发条件**: 攻击者构造一个 strip-organized TIFF 文件，将 PLANARCONFIG 设置为 PLANARCONFIG_CONTIG，通过设置超大 ImageWidth（如 65536）、SamplesPerPixel（如 4）、BitsPerSample（如 8）使得 `rowsperstrip × imagewidth × spp × bps/8 > UINT32_MAX`（即 rowsperstrip × 65536 × 4 × 1 > 2^32，当 rowsperstrip ≥ 16384 时触发）；同时 ImageLength 非零以使 put 循环执行。
- **安全影响**: 攻击者可通过精心构造的 TIFF 导致 libtiff 堆越界读取，读取到的堆内部数据写入调用方 raster 缓冲区，造成堆内存信息泄露（C:H）；若越界读取命中未映射地址，触发 SIGSEGV 崩溃（A:H）用于 DoS 攻击。

<!-- AUDIT_PROMPT_VERSION: 1 -->
