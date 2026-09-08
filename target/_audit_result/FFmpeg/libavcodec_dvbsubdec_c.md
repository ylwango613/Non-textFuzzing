I've completed the full analysis. Here is the confirmed memory safety finding:

## VULN: Heap OOB Read in dvbsub_parse_pixel_data_block – Missing Bounds Check in Map Table Redefinition Cases 0x20/0x21/0x22
- **漏洞类别**: memory-safety
- **函数**: dvbsub_parse_pixel_data_block()
- **行号**: 961-974
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted DVB subtitle media file (MPEG-TS / raw .dvbsub packet)
- **外部触发路径**: `ffmpeg -i crafted.ts -f null -` → `dvbsub_decode()` (dvbsubdec.c:1449) → `dvbsub_parse_object_segment()` (dvbsubdec.c:989) → `dvbsub_parse_pixel_data_block()` (dvbsubdec.c:871) → OOB read at lines 961-974
- **描述**: 在 `dvbsub_parse_pixel_data_block()` 的主解析循环（line 916）中，循环条件仅检查 `buf < buf_end`。进入循环后通过 `switch (*buf++)` 消费一个命令字节（line 922），此后对命令字节的 `buf` 指针可能已等于 `buf_end`。但在 case 0x20（line 961-965）、case 0x21（line 967-970）、case 0x22（line 971-974）分支中，代码分别继续从 `buf` 读取 2 字节、4 字节、16 字节来填充 map 表（`map2to4`/`map2to8`/`map4to8`），**完全没有对 `buf < buf_end` 的二次边界检查**。当攻击者将 `top_field_len`（来自 Object Segment 头部的 16-bit 字段）设为极小值（如 1），并让像素数据块唯一字节为 0x22，解码器将越界读取 16 字节超出 heap 分配的 packet 数据缓冲区。读取到的越界数据被写入栈局部数组 `map4to8[0..15]`，若后续有 case 0x11 的像素串使用此 map，泄漏的 heap 字节将作为颜色索引写入区域像素缓冲（无二次指针跳转，写目标有界），但原始读越界本身可造成崩溃或堆数据泄漏。
- **触发条件**: 攻击者构造包含 DVB 字幕（AV_CODEC_ID_DVB_SUBTITLE）的媒体文件（MPEG-TS、MPEG-PS 等）。在 Object Segment 的 Top Field 数据区域中，将 `top_field_len` 设为 1，唯一字节值为 `0x22`（或 `0x21`/`0x20`）。当 FFmpeg 播放或转码此文件时，DVB 字幕解码器处理该像素数据块，触发越界读取。
- **安全影响**: 最严重情况下：（1）**堆内存信息泄漏**——越界读出的堆数据作为调色板索引存入 region 像素缓冲，攻击者可通过观察解码后图像的颜色来推断相邻 heap 块内容，用于泄漏指针/ASLR bypass；（2）**崩溃（DoS）**——若 `buf_end + 16` 跨越页边界，非法读触发 SIGSEGV，导致 FFmpeg 进程崩溃。

<!-- AUDIT_PROMPT_VERSION: 1 -->
