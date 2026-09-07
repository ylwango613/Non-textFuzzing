I now have a complete picture of the file. Let me compile the definitive analysis based on all five batches.

**Batch analysis notes:**

**Lines 1138–1145 (OJPEGWriteHeaderInfo):**  
`subsampling_convert_ybuflen = ylinelen * ylines` (uint32 × uint32, no overflow check). With `strile_width` = 0x20000001 and `subsampling_hor=1, subsampling_ver=1`:
- `ylinelen = 0x20000008`, `ylines = 8`
- `ybuflen = 0x20000008 * 8 = 0x100000040` → truncates to **0x40 = 64** (uint32 overflow)
- `clinelen = 0x20000008`, `cbuflen = 64` (same overflow)
- `ycbcrbuflen = 64 + 128 = 192` → `_TIFFmalloc(192)` allocated

**Lines 1165–1170:** Row pointers set as `ybuf + n * ylinelen`:
- n=1 → `ybuf + 0x20000008` (537 MB past the 192-byte buffer)
- n=2 → `ybuf + 0x40000010` (>1 GB past)

**Lines 705/711/785:** `jpeg_read_raw_data_encap()` writes decompressed JPEG data through those row pointers → **heap buffer overflow**.

**`strile_width` source:** For non-tiled TIFF: `sp->strile_width = td_imagewidth`. For tiled: `sp->strile_width = td_tilewidth`. Both are uint32 from the TIFF IFD, no upper-bound validation before use in the overflow arithmetic. The SOF-path width check (lines 1552-1561) limits the JPEG-embedded SOF width to uint16 only when SOF is present, but does **not** constrain `strile_width` itself; the buffer sizing always uses `strile_width`.

**Code path to trigger:** When the JPEG stream has no SOF marker (table-from-tags path, `sof_log == 0`), `strile_width` feeds straight into the allocation arithmetic with no constraint. With tiled TIFF, `td_tilewidth` can also differ from `td_imagewidth`, allowing the SOF check on `image_width` to be satisfied separately.

No other memory-safety vulnerabilities of equivalent severity were found (DHT/DQT allocations are bounded by uint16 header length; sof_c/sof_hv/sof_tq arrays are bounded by the 1-or-3 SamplesPerPixel check; ycbcrimagelen is bounded by fixed small constants).

## VULN: Integer overflow in OJPEGWriteHeaderInfo YCbCr buffer sizing → heap buffer overflow via libjpeg row pointers
- **漏洞类别**: memory-safety
- **函数**: OJPEGWriteHeaderInfo()
- **行号**: 1138-1170
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted TIFF file
- **外部触发路径**: tiffsplit main() → TIFFOpen() → TIFFReadDirectory() → [first strip/tile decode] → OJPEGPreDecode() → OJPEGSubsamplingCorrect() → OJPEGReadHeaderInfo() → OJPEGWriteHeaderInfo() [integer overflow at lines 1142-1144, under-allocation] → OJPEGDecodeRaw() → jpeg_read_raw_data_encap() [writes through out-of-bounds row pointers]
- **描述**: 在 OJPEGWriteHeaderInfo() 的第 1142–1144 行，`subsampling_convert_ybuflen = sp->subsampling_convert_ylinelen * sp->subsampling_convert_ylines`（均为 uint32）发生整数溢出。`strile_width` 取自 TIFF IFD 的 `ImageWidth`（非瓦片）或 `TileWidth`（瓦片）标签，为不受上界约束的 uint32 值。当 `strile_width` 足够大时（例如 0x20000001，subsampling 1,1），`ylinelen = 0x20000008`，乘以 `ylines = 8` 后溢出 uint32 得到 0x40（=64）；加上两份 `cbuflen` 溢出后 `_TIFFmalloc` 仅分配 192 字节。随后在第 1165–1170 行为 ycbcrbuf 设置行指针时，第 1 行起的每个指针都计算为 `ybuf + n * 0x20000008`，指向分配区域后数百 MB 以外的堆内存。当 libjpeg 通过 `jpeg_read_raw_data_encap()` 调用这些行指针写入解压数据时，发生堆缓冲区溢出。
- **触发条件**: 构造包含以下字段的 TIFF 文件：(1) 压缩类型 COMPRESSION_OJPEG；(2) Photometric = YCbCr，SamplesPerPixel = 3，PlanarConfig = CONTIG；(3) ImageWidth 或 TileWidth > 约 0x1FFFFFFF（使 ylinelen × 8 溢出 uint32）；(4) YCbCrSubSampling = 1,1；(5) 可含有效 JpegInterchangeFormat 流或 JpegQTables/JpegDcTables/JpegAcTables 标签，以使头部解析成功。攻击者将此文件作为 tiffsplit 的输入。
- **安全影响**: 最坏情况下攻击者通过精心布局堆实现任意写原语，进而达到远程代码执行（RCE）；在利用难度较高时至少造成进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
