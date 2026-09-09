Both vulnerabilities are confirmed. `bytestream_get_byte()` has **no bounds checking** — it's a bare pointer dereference+increment. Final analysis:

**VULN 1** (`parse_presentation_segment`, lines 463-468): The guard at line 449 checks only 8 bytes for the base object. After consuming those 8 bytes, if `composition_flag & 0x80` is set, 8 more bytes are read with no re-check of `buf_end`. Attacker sets `segment_length` so exactly 8 bytes remain for one object entry and sets the crop bit → 8-byte heap over-read.

**VULN 2** (`parse_palette_segment`, lines 354-374): Loop condition is `buf < buf_end` (1 remaining byte suffices to enter), but each iteration consumes 5 bytes. With `(segment_length - 2) % 5 != 0`, the last iteration reads 1–4 bytes beyond `buf_end`.

## VULN: parse_presentation_segment Missing Bounds Check for Crop Data OOB Read
- **漏洞类别**: memory-safety
- **函数**: parse_presentation_segment()
- **行号**: 449-468
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted media file
- **外部触发路径**: ffmpeg -i <crafted.mkv/sup> -f null - -> avformat_open_input() -> demuxer packet read -> avcodec_decode_subtitle2() -> decode() -> parse_presentation_segment()
- **描述**: 在 `parse_presentation_segment` 的对象遍历循环（line 445）中，line 449 的边界检查 `buf_end - buf < 8` 只验证了对象基本字段（id、window_id、composition_flag、x、y）所需的 8 个字节。读取这 8 字节后，`buf` 向前移动了 8 个字节。当 `object->composition_flag & 0x80` 裁剪标志被设置时（line 463），代码连续调用 4 次 `bytestream_get_be16`（共 8 字节，lines 464-467）读取 crop_x/crop_y/crop_w/crop_h，而此时没有任何对 `buf_end - buf >= 8` 的再次校验。`bytestream_get_byte/be16` 是无边界检查的裸指针解引用（bytestream.h line 45-46），因此这 8 字节读取会越过 `buf_end`（即越过该 segment 的合法数据范围），发生堆越界读取，读入相邻堆内存或 AVPacket 填充区域。
- **触发条件**: 攻击者构造一个含 PGS 字幕的 MKV/HDMV Transport Stream 文件，其中 Presentation Segment 的 `segment_length` 恰好覆盖对象头部 8 字节（例如 segment_length=19，仅包含 11 字节公共头部 + 8 字节单对象基本字段），同时将该对象的 `composition_flag` 第 7 位（0x80）置为 1，使解码器在无效内存区域读取 8 字节裁剪参数。
- **安全影响**: 堆越界读取最多 8 字节相邻堆内存。在开启 ASAN/Valgrind 的构建中必然崩溃（拒绝服务）；在普通构建中若读入未映射内存页亦触发 SIGSEGV；读取到的相邻堆数据（指针、元数据）被赋值给 crop_x/crop_y/crop_w/crop_h，理论上可被攻击者通过字幕渲染颜色通道回显造成堆内存信息泄漏。

## VULN: parse_palette_segment Partial Palette Entry Heap OOB Read
- **漏洞类别**: memory-safety
- **函数**: parse_palette_segment()
- **行号**: 354-374
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted media file
- **外部触发路径**: ffmpeg -i <crafted.mkv/sup> -f null - -> avformat_open_input() -> demuxer packet read -> avcodec_decode_subtitle2() -> decode() -> parse_palette_segment()
- **描述**: `parse_palette_segment` 中的调色板解析循环（line 354）以 `buf < buf_end` 为条件，该条件仅需要 1 字节剩余即可进入循环体，但循环体每次迭代顺序调用 5 次 `bytestream_get_byte`，消耗 5 字节（color_id、y、cr、cb、alpha，lines 355-359）。当调色板数据部分（segment 数据减去 2 字节头部）字节数不是 5 的倍数时——即 `(segment_length - 2) % 5 != 0`——最后一次迭代将在只有 1~4 字节合法数据的情况下读取 5 字节，导致最多 4 字节的堆越界读取。读取越界字节后，这些数据被当作 Y/Cr/Cb/Alpha 经 YUV→RGB 转换写入 `palette->clut[color_id]`（color_id 始终为 0-255，写入位置本身合法），整个过程造成越界读取和调色板数据污染。
- **触发条件**: 攻击者构造含 PGS 字幕的媒体文件，设置 Palette Segment 的 `segment_length` 使其调色板数据字节数（`segment_length - 2`）不是 5 的倍数（如 `segment_length = 8`，调色板数据为 6 字节，第一次完整读取 5 字节，剩余 1 字节时再次进入循环读 5 字节，越界 4 字节）。
- **安全影响**: 每次处理此类畸形 palette segment 时越界读取最多 4 字节堆数据；越界读取的字节被用作 YUV 颜色分量，经色彩空间转换后存入调色板 CLUT，攻击者可通过观察渲染出的字幕颜色值推断相邻堆内存内容（侧信道信息泄漏）；若越界访问恰好触及未映射内存页则触发 SIGSEGV（拒绝服务）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
