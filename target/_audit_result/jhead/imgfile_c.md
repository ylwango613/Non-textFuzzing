I have completed the full audit. The evidence is clear:

- `ImageInfo.ThumbnailSize` is declared `int` (jhead.h:130)
- EXIF sets it via `ThumbnailSize = (unsigned)ConvertAnyFormat(…)` with value 0xFFFFFFFF → `int` -1 (exif.c:863)
- The bounds check `if (ThumbnailSize > ExifLength-ThumbnailOffset)` uses signed comparison — `-1 > positive` is false, so no clamping (exif.c:982)
- `-1` is stored into `ImageInfo.ThumbnailSize` (exif.c:992)
- `imgfile.c:334` checks `== 0`, not `<= 0`; -1 ≠ 0, so processing continues
- `fwrite(ThumbnailPointer, ImageInfo.ThumbnailSize, 1, file)` at imgfile.c:365: `-1` implicitly converts to `size_t` = SIZE_MAX → massive heap OOB read
- The intentional `malloc(itemlen+20)` padding (jpgfile.c:130) is only 20 bytes and does not mitigate a SIZE_MAX read

## VULN: SaveImgThumbnail Heap OOB Read via Negative ThumbnailSize Sign Error
- **漏洞类别**: memory-safety
- **函数**: SaveImgThumbnail()
- **行号**: imgfile.c:365 (根因: exif.c:863, exif.c:982, exif.c:992)
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.1 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted JPEG file
- **外部触发路径**: jhead main() → SaveImgThumbnail() [imgfile.c:527, via `-st` flag] → fwrite(ThumbnailPointer, ImageInfo.ThumbnailSize, 1, file) [imgfile.c:365]; ImageInfo.ThumbnailSize 在 process_EXIF() → ProcessExifDir() [exif.c:863/982/992] 中被设置为负值
- **描述**: `ImageInfo.ThumbnailSize` 声明为 `int`（jhead.h:130）。在 exif.c:863，TAG_THUMBNAIL_LENGTH 的文件值被赋值为 `ThumbnailSize = (unsigned)ConvertAnyFormat(ValuePtr, Format)`：当文件中该字段 ≥ 2^31（如 0xFFFFFFFF）时，`(unsigned)` 转换得到 4294967295，再赋给 `int ThumbnailSize` 产生 -1（有符号截断）。exif.c:982 的截断检查 `if (ThumbnailSize > ExifLength-ThumbnailOffset)` 使用有符号比较，-1 小于任何正数，截断逻辑被跳过，-1 直接写入 `ImageInfo.ThumbnailSize`。imgfile.c:334 的卫语句检查 `== 0` 而非 `<= 0`，-1 ≠ 0 不触发提前退出。最终 imgfile.c:365 的 `fwrite(ThumbnailPointer, ImageInfo.ThumbnailSize, 1, file)` 将 `int -1` 隐式转换为 `size_t` = SIZE_MAX（64 位下约 1.8×10^19），导致从堆缓冲区 ThumbnailPointer 开始无界读取，直到触发 SIGSEGV 为止所有可访问的堆/库/栈内存均被写入输出文件。
- **触发条件**: 攻击者构造 JPEG 文件，使 EXIF IFD1 中 TAG_THUMBNAIL_OFFSET（0x0201）设置为小正数（如 0x10，确保通过 exif.c:981 的 `ThumbnailOffset <= ExifLength` 检查），TAG_THUMBNAIL_LENGTH（0x0202）设置为 0xFFFFFFFF 或任意 ≥ 2^31 的值；用户执行 `jhead -st <output_file> <crafted.jpg>`。
- **安全影响**: 堆越界读取——进程所有可读堆/内存内容（含堆指针、函数指针、敏感数据）被写入攻击者指定输出文件，造成高危信息泄露（可用于 ASLR bypass）；同时在读取至未映射页时触发 SIGSEGV 导致进程崩溃（DoS）。若 jhead 作为服务端图片处理管道运行，此漏洞可致进程内存内容外泄。

<!-- AUDIT_PROMPT_VERSION: 1 -->
