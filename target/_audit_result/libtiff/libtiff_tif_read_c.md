The analysis is complete. The key finding is confirmed: TIFFFillStrip/TIFFFillTile both have explicit comments about the unsafe single-comparison check and use the safe two-part check, but `TIFFReadRawStrip1` (line 198) and `TIFFReadRawTile1` (line 440) still use the unsafe `offset + size > tif_size` comparison that overflows for crafted TIFF stripoffset values. This is reachable directly from tiffsplit via `cpStrips → TIFFReadRawStrip → TIFFReadRawStrip1` and `cpTiles → TIFFReadRawTile → TIFFReadRawTile1`.

## VULN: TIFFReadRawStrip1 mmap bounds-check uint32 overflow → OOB read
- **漏洞类别**: memory-safety
- **函数**: TIFFReadRawStrip1()
- **行号**: 197-209
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.1 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted TIFF file
- **外部触发路径**: tiffsplit main() → TIFFOpen() → tiffcp() → cpStrips() → TIFFReadRawStrip() → TIFFReadRawStrip1() (mmap 分支, line 197-208)
- **描述**: 在内存映射（mmap）路径中，函数对 strip 的可读性做边界检查的代码为 `td->td_stripoffset[strip] + size > tif->tif_size`（第 197 行）。`td_stripoffset[strip]` 类型为 `toff_t`（uint32），`size` 类型为 `tsize_t`（int32），两者相加按 uint32 模运算处理。当攻击者将 TIFF 文件中的 StripOffset 字段设置为接近 UINT32_MAX 的值（如 0xFFFFFF00），且 StripByteCount 为小正整数（如 256）时：`0xFFFFFF00 + 256 = 0x100000000` 在 uint32 下溢出为 `0`，条件 `0 > tif_size` 为假，边界检查被绕过。随后 `_TIFFmemcpy(buf, tif->tif_base + 0xFFFFFF00, 256)` 从映射基址 +4GiB 偏移处读取数据，该地址远超实际映射文件区域，触发 OOB read。对比同文件的 `TIFFFillStrip` 函数（第 300–310 行），其注释明确指出该加法会溢出并采用两步安全比较 `bytecount > tif_size || offset > tif_size - bytecount`，但 `TIFFReadRawStrip1` 的修复补丁从未应用。
- **触发条件**: 构造 TIFF 文件，设置 `StripOffset[n]` ≥ `UINT32_MAX - StripByteCount[n] + 1`（如 StripOffset=0xFFFFFF00, StripByteCount=256），令 `(offset + bytecount) mod 2^32 ≤ tif_size`。文件在具有 mmap 支持的系统（Linux 默认开启 HAVE_MMAP）上用 tiffsplit 解析即可触发。
- **安全影响**: 可靠 crash（SIGSEGV/DoS）；若进程地址空间中 mmap_base+offset 恰好落入已映射页（如共享库、堆等），可造成堆外任意地址内容被写入栈/堆缓冲区（信息泄露）；在 32 位进程中地址回绕后可能进一步升级为可利用的堆缓冲区溢出。

## VULN: TIFFReadRawTile1 mmap bounds-check uint32 overflow → OOB read
- **漏洞类别**: memory-safety
- **函数**: TIFFReadRawTile1()
- **行号**: 440-451
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.1 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted TIFF file
- **外部触发路径**: tiffsplit main() → TIFFOpen() → tiffcp() → cpTiles() → TIFFReadRawTile() → TIFFReadRawTile1() (mmap 分支, line 440-451)
- **描述**: 与 TIFFReadRawStrip1 存在完全相同的缺陷：第 440 行 `if (td->td_stripoffset[tile] + size > tif->tif_size)` 使用 uint32 模运算，当 `td_stripoffset[tile]` 接近 UINT32_MAX 时加法溢出导致边界检查失效。`TIFFFillTile`（第 535–544 行）同样有明确注释并已采用两步安全比较修复，而 `TIFFReadRawTile1` 的相应修复缺失。绕过检查后，第 451 行 `_TIFFmemcpy(buf, tif->tif_base + td->td_stripoffset[tile], size)` 将从远超文件映射边界的地址读取数据。
- **触发条件**: 构造带瓦片格式（tiled TIFF）的文件，设置 `TileOffset[n]` 使得 `TileOffset[n] + TileByteCount[n]` 在 uint32 下溢出且结果 ≤ `tif_size`（如 TileOffset=0xFFFFFF00, TileByteCount=256, 文件大小=1024），tiffsplit 以瓦片图像调用 cpTiles 即可触发。
- **安全影响**: 与 strip 变体相同：可靠 crash（SIGSEGV/DoS）；潜在任意地址 OOB read → 信息泄露或（32 位环境下）堆溢出利用。

<!-- AUDIT_PROMPT_VERSION: 1 -->
