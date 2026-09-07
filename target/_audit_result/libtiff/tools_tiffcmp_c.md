I have confirmed the vulnerability. For SEPARATE config, `TIFFScanlineSize` = `imagewidth * bps / 8` bytes (correctly packed), but `SeparateCompare` iterates `imagewidth` times doing byte-by-byte access — so for bps=1 it reads 8× beyond the allocated buffer.

## VULN: SeparateCompare heap OOB read for sub-8-bit pixels in mixed PlanarConfig
- **漏洞类别**: memory-safety
- **函数**: SeparateCompare()
- **行号**: 484-505 (触发条件判断: 178-182)
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 6.1 (AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted TIFF file pair
- **外部触发路径**: tiffcmp main() → tiffcmp() [line 149] → TIFFScanlineSize(tif1) [line 172, allocates buf1 = imagewidth*bps/8 bytes] → TIFFScanlineSize(tif2) [line 173, allocates buf2 = imagewidth*bps/8 bytes] → switch pack(PLANARCONFIG_SEPARATE, PLANARCONFIG_CONTIG) [line 185] → TIFFReadScanline() → SeparateCompare() [line 192 / line 204] → byte-by-byte loop reads imagewidth bytes from imagewidth*bps/8-byte buffer
- **描述**: `TIFFScanlineSize()` 对 PLANARCONFIG_SEPARATE 配置的文件返回 `imagewidth * bitspersample / 8` 字节（位图打包后的大小），当 `bitspersample < 8` 时每个字节存储多个像素。`tiffcmp()` 以此大小分配 `buf1`/`buf2`（行 172-173）。但当 tif1 与 tif2 使用不同 PlanarConfig（一个 SEPARATE，一个 CONTIG）时，代码会调用 `SeparateCompare()`（行 192/204）。该函数在循环中以"一像素一字节"步进（`cp1 += samplesperpixel`、`p2++`）迭代恰好 `imagewidth` 次（行 492），完全不考虑位打包。当 `bitspersample=1` 时，循环将读取 `imagewidth` 字节，而缓冲区只有 `imagewidth/8` 字节，造成超出末尾 `7*imagewidth/8` 字节的堆越界读取。行 178 的 guard 仅当 `samplesperpixel > 1` 时才阻止混合 PlanarConfig 路径，当 `samplesperpixel == 1` 时任由其通过。
- **触发条件**: 攻击者提供两个 TIFF 文件：file1 设置 `PLANARCONFIG_SEPARATE`（或 CONTIG），file2 设置 `PLANARCONFIG_CONTIG`（或 SEPARATE），两者均设置 `BitsPerSample=1`（或 2/4）、`SamplesPerPixel=1`、`ImageWidth` 足够大（如 65536）。两文件的 BitsPerSample、SamplesPerPixel、ImageWidth 必须相等以通过 CheckShortTag/CheckLongTag 校验。
- **安全影响**: 读取 `buf1`/`buf2` 末尾之后的堆内存，可泄露相邻堆对象内容（信息泄露），或访问未映射内存导致进程崩溃（DoS/SIGSEGV）；在特定堆布局下可能辅助更深层利用。

<!-- AUDIT_PROMPT_VERSION: 1 -->
