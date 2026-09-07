Based on my thorough analysis of all source files, I have identified the following confirmed memory-safety vulnerabilities.

## VULN: GPS IFD Unchecked Component-Count Loop OOB Read in WebP EXIF
- **漏洞类别**: memory-safety
- **函数**: ProcessGpsInfo()
- **行号**: 141-155 (gpsinfo.c)
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.1 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted WebP file
- **外部触发路径**: jhead main() → ProcessFile() → ReadImgFile() → ReadWebpSections() → process_EXIF(Data, ChunkLen) → ProcessExifDir() [TAG_GPSINFO] → ProcessGpsInfo() → for(a=0;a<3;a++) loop reads beyond allocation
- **描述**: In `ProcessGpsInfo()` (gpsinfo.c:141-155), when processing `TAG_GPS_LAT` or `TAG_GPS_LONG`, the code **always iterates `a` from 0 to 2** (reads 3 rational components) regardless of the actual `Components` count parsed from the IFD entry. The bounds check at line 110 only validates `ByteCount = Components * ComponentSize` bytes: `if (OffsetVal+ByteCount > ExifLength)`. If the attacker sets `Components=1` with `Format=FMT_URATIONAL` (ComponentSize=8), `ByteCount=8`, and `OffsetVal = ExifLength-8`, the check passes. However the loop then reads up to `ValuePtr+23` (components at offsets 0, 8, 16 plus 4-byte denominators). For **WebP files**, `ReadWebpSections()` allocates the EXIF chunk buffer as `malloc(ReadLen)` **without any extra padding** (unlike JPEG which uses `malloc(itemlen+20)`). With `ChunkLen` (even) = N: `ReadLen=N`, valid indices are `[0..N-1]`, but the loop reads up to `Data+N-8+23 = Data+N+15`, which is **16 bytes past the end** of the allocation. This is a heap out-of-bounds read that will crash under ASAN/Valgrind and may crash in production depending on heap layout.
- **触发条件**: 构造一个 WebP 文件，其 EXIF chunk 中包含 GPS IFD，GPS IFD 中的 TAG_GPS_LAT 或 TAG_GPS_LONG 条目设置 `Components=1`、`Format=5 (FMT_URATIONAL)`、`OffsetVal=ChunkLen-8`。调用 `jhead crafted.webp` 无需任何额外参数即可触发。
- **安全影响**: 堆越界读取（最多超出约16字节），导致进程崩溃（DoS）或泄露堆元数据/邻近分配内存内容（信息泄露）。若 ValuePtr 恰好位于内存页边界，可触发 SIGSEGV。

## VULN: ExifBytesActuallyUsed Negative-Index OOB Read for PNG
- **漏洞类别**: memory-safety
- **函数**: ExifBytesActuallyUsed()
- **行号**: 1220-1226 (exif.c)
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 3.9 (AV:L/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:L)
- **严重程度**: Low
- **攻击向量**: crafted PNG file with -zt flag
- **外部触发路径**: jhead -zt main() → ProcessFile() → TrimImgExifTrailingZeros() → GetImgExifSectionData() → ExifBytesActuallyUsed(ExifData, Size)
- **描述**: In `ExifBytesActuallyUsed()` (exif.c:1222-1226), the loop `for(;;NewSize--)` checks `if (ExifData[NewSize-1]) break;` **before** the termination guard `if (NewSize <= ThumbnailEndIndex) break;`. When `ThumbnailEndIndex = ImageInfo.ThumbnailOffset + ImageInfo.ThumbnailSize = 0` (which occurs on a PNG EXIF with all data inline and no thumbnail), and all bytes of the EXIF buffer are zero (trailing zeros), `NewSize` decrements to 0. At that point, `ExifData[0-1] = ExifData[-1]` is accessed **before** the guard `if (0 <= 0)` fires. For PNG files, `GetImgExifSectionData()` returns `ExSection->Data` directly (no +8 offset), so `ExifData[-1]` is the byte immediately before the `malloc`'d chunk — a one-byte heap underread. For JPEG, `ExifData = ExSection->Data+8`, so `ExifData[-1] = ExSection->Data+7` which falls within the allocation and is benign.
- **触发条件**: 构造一个 PNG 文件，其 eXIf chunk 中包含全零结尾的 EXIF 数据（如 ThumbnailOffset=0, ThumbnailSize=0，所有 IFD 数据内联），然后运行 `jhead -zt crafted.png`。ASAN 构建下会立即报告 heap-underflow。
- **安全影响**: 单字节堆下读（heap underread）。可导致读取 malloc 元数据，ASAN 报告 heap-buffer-underflow；在无保护的生产环境中行为取决于堆分配器实现，最坏情况下造成程序崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
