I've completed the full analysis across all 9066 lines. Here is the final audit report:

## VULN: Integer Overflow in loadImage() Strip buffsize → Heap OOB Write
- **漏洞类别**: memory-safety
- **函数**: loadImage()
- **行号**: 5955-5966
- **CWE**: CWE-190 (Integer Overflow or Wraparound)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted TIFF file
- **外部触发路径**: tiffcrop main() → loadImage() → _TIFFmalloc(buffsize=0) → readContigStripsIntoBuffer() → TIFFReadEncodedStrip() writes actual strip data → heap OOB write
- **描述**: 在 loadImage() 中，`nstrips` 被声明为 `uint16`（第5725行），而 `TIFFNumberOfStrips()` 返回 `tstrip_t`（uint32）；当文件包含 >65535 条带时被截断。此后 `buffsize = stsize * nstrips`（第5957行）以 uint32 算术运算，当 stsize 与 nstrips 之积超过 2^32 时绕回到0或小值。备用检查 `(length * width * spp * bps + 7) / 8`（第5959-5961行）中 length、width 均为 uint32，spp/bps 为 uint16，四值连乘极易整数溢出（例如 width=0x8000, height=0x8000, spp=4, bps=32 时乘积为 2^34，截断为0），导致两路校验均溢出为0，最终 `_TIFFmalloc(0)` 分配极小缓冲区，但 `readContigStripsIntoBuffer()` 在循环中向该缓冲区写入所有条带的实际解码数据，造成堆越界写入。
- **触发条件**: 构造 TIFF 文件，ImageWidth=0x8000、ImageLength=0x8000、BitsPerSample=32、SamplesPerPixel=4、RowsPerStrip=1，并提供至少一个包含实际像素数据的条带；无需额外命令行参数，直接 `tiffcrop input.tif output.tif` 即可触发。
- **安全影响**: 堆缓冲区溢出，攻击者可控写入大量连续堆内存，在典型 ASLR+Heap Hardening 环境下可能实现任意代码执行（RCE），或至少造成进程崩溃（DoS）。

## VULN: Integer Overflow in loadImage() Tile buffsize (uint16 ntiles Truncation) → Heap OOB Write
- **漏洞类别**: memory-safety
- **函数**: loadImage()
- **行号**: 5927-5944
- **CWE**: CWE-190 (Integer Overflow or Wraparound)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted TIFF file
- **外部触发路径**: tiffcrop main() → loadImage() → _TIFFmalloc(buffsize=0) → readContigTilesIntoBuffer() → _TIFFmemcpy(bufp, ...) writes tile data beyond allocation → heap OOB write
- **描述**: 在 loadImage() 的瓦片分支（第5927-5944行），`ntiles` 同样声明为 `uint16`（第5725行），接收 `TIFFNumberOfTiles()` 返回的 uint32 值时发生截断。当文件包含恰好 65536 的整数倍个瓦片时（例如 512×512 = 262144 tiles，262144 % 65536 = 0），`ntiles` 被截断为 0。此后 `buffsize = tlsize * ntiles = tlsize * 0 = 0`（第5933行），备用检查 `ntiles * tl * tile_rowsize = 0 * ... = 0`（第5936-5944行）同样为0，没有第二道基于 `width*height*bps*spp` 的校验（不像条带路径），因此 `_TIFFmalloc(0)` 被调用。随后 `readContigTilesIntoBuffer()` 对所有 imagelength/tl × imagewidth/tw 个瓦片调用 `_TIFFmemcpy(bufp, ...)` 并递增 `bufp`，将全部瓦片数据写入零字节分配的缓冲区，造成堆越界写入。
- **触发条件**: 构造 tiled TIFF，使 TIFFNumberOfTiles 返回 65536 的正整数倍（例如总瓦片数 = 65536）；实际瓦片内含真实像素数据。无需额外命令行参数。
- **安全影响**: 堆缓冲区溢出；可控写入任意长度堆内存，潜在 RCE 或 DoS。

## VULN: Integer Overflow in rotateImage() Rotation Buffer → Heap OOB Write via ORIENTATION Tag
- **漏洞类别**: memory-safety
- **函数**: rotateImage()
- **行号**: 8225-8250
- **CWE**: CWE-190 (Integer Overflow or Wraparound)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted TIFF file
- **外部触发路径**: tiffcrop main() → loadImage()（设 image.adjustments = ROTATECW_90 via ORIENTATION tag） → correct_orientation() → rotateImage() → _TIFFmalloc(overflow_buffsize) → 90° 旋转循环写入 width×length 像素到undersized rbuff → heap OOB write
- **描述**: `rotateImage()` 第8225-8230行计算旋转缓冲区大小：`rowsize = ((bps * spp * width) + 7) / 8`，`colsize = ((bps * spp * length) + 7) / 8`，然后 `buffsize = (colsize + 1) * width` 或 `(rowsize + 1) * length`，这些均为 uint32 算术运算。当 colsize（或 rowsize）足够大时，乘以 width（或 length）导致 uint32 溢出到一个小正整数。例如 width=length=65536、bps=8、spp=4 时，rowsize=colsize=262144，`(colsize + 1) * width = 262145 * 65536 = 17,180,797,952 mod 2^32 = 65536`，因此 `_TIFFmalloc(65536)` 成功分配64KB。但随后的90°旋转循环逐像素写入，总写入量为 65536 × 65536 × 4 = 16 GB，远超64KB，产生严重堆越界写入。此漏洞仅通过设置 TIFF ORIENTATION 标签（tag 0x0112）值为6（ORIENTATION_RIGHTTOP）即可触发，无需任何命令行标志。
- **触发条件**: 构造 TIFF 文件，设置 ORIENTATION = 6（RIGHTTOP），ImageWidth=65536、ImageLength=65536、BitsPerSample=8、SamplesPerPixel=4，并提供有效的图像数据。`tiffcrop input.tif output.tif` 时自动触发方向校正→旋转。
- **安全影响**: 堆缓冲区大量越界写入（写入数据量可达 GB 级别），rbuff 后的整个堆结构均被破坏，高概率 RCE；退而求其次也是确定性 DoS（进程崩溃）。

## VULN: Integer Overflow in writeBufferToSeparateStrips() rowstripsize → Heap OOB Write
- **漏洞类别**: memory-safety
- **函数**: writeBufferToSeparateStrips()
- **行号**: 1148-1165
- **CWE**: CWE-190 (Integer Overflow or Wraparound)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted TIFF file
- **外部触发路径**: tiffcrop main() → writeCroppedImage() → writeBufferToSeparateStrips() → _TIFFmalloc(rowstripsize=0) → extractContigSamplesToBuffer(obuf, ..., width) → _TIFFmemcpy(dst, src, dst_rowsize) → heap OOB write
- **描述**: `writeBufferToSeparateStrips()` 第1149行计算 `rowstripsize = rowsperstrip * bytes_per_sample * (width + 1)`，三个 uint32 值连乘，当 width 接近 UINT32_MAX（或使乘积溢出）时结果绕回为0。例如 rowsperstrip=4、bytes_per_sample=2（bps=16）、width=0x3FFFFFFF：`(width+1) = 0x40000000`，`4 * 2 * 0x40000000 = 0x200000000 mod 2^32 = 0`。此后 `_TIFFmalloc(0)` 分配零字节缓冲区 `obuf`，`memset(obuf, 0, 0)` 无操作，但 `extractContigSamplesToBuffer(obuf, src, nrows, width, ...)` 按真实 width 写入完整行数据，造成堆越界写入。该路径在输入为 PLANARCONFIG_SEPARATE 配置的 TIFF 时触发（可由攻击者通过 TIFF IFD 中的 PlanarConfiguration 标签控制），无需额外命令行参数。
- **触发条件**: 构造 PLANARCONFIG_SEPARATE 的 TIFF（PlanarConfiguration=2），设置超大 ImageWidth 使 `rowsperstrip * bytes_per_sample * (width+1)` 溢出为0。
- **安全影响**: 堆越界写入，后续堆元数据破坏，潜在 RCE 或 DoS。

## VULN: Integer Overflow in writeImageSections() sectsize → Undersized Section Buffer → Heap OOB Write
- **漏洞类别**: memory-safety
- **函数**: writeImageSections()
- **行号**: 6859-6869
- **CWE**: CWE-190 (Integer Overflow or Wraparound)
- **CVSS v3.1**: 7.3 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted TIFF file + `-S` option
- **外部触发路径**: tiffcrop main() -S option → computeOutputPixelOffsets() → writeImageSections() → createImageSection(sectsize_overflow) → _TIFFmalloc(tiny) → extractImageSection() → _TIFFmemcpy(sect_buff+dst_offset, ...) → heap OOB write
- **描述**: `writeImageSections()` 第6859-6860行计算每个分段的缓冲区大小：`sectsize = (uint32)ceil((width * image->bps + 7) / (double)8) * image->spp * length`。其中 `width * image->bps` 是 uint32 * uint16 的整数乘法，在整数域溢出后才转换为 double 进行除法（溢出值已被截断），再将 ceil 结果强转 uint32 后乘以 `image->spp * length`，后者也可溢出。例如 width=0x100000、bps=64、spp=4、length=0x100000 时：`width * bps = 0x100000 * 64 = 0x4000000`（正常），`(0x4000000 + 7) / 8.0 = 0x800000`，`0x800000 * 4 = 0x2000000`，再 `* 0x100000 = 0x2000000000000 mod 2^32 = 0`，sectsize=0。随后 `createImageSection(0, ...)` → `_TIFFmalloc(0)` 分配零字节缓冲区，`extractImageSection()` 调用 `_TIFFmemcpy(sect_buff + dst_offset, ...)` 按真实 section 尺寸写入数据，造成堆越界写入。
- **触发条件**: 需要 `-S cols:rows` 选项，构造 TIFF 使 section 的 width × bps × spp × length 在 uint32 内溢出。
- **安全影响**: 堆越界写入，可能导致 RCE 或 DoS。

<!-- AUDIT_PROMPT_VERSION: 1 -->
