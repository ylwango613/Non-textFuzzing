This confirms `tif_rawdata` is heap-allocated (or memory-mapped) with exactly `bytecount` bytes valid; `tif_rawcc` is set to `bytecount`. Any read past `tif_rawcc` in `PackBitsDecode` is an OOB read from either a heap buffer or a mapped file region.

**Analysis complete.** Two distinct heap/mmap OOB-read vulnerabilities in `PackBitsDecode`:

1. **Line 261** — Literal-copy branch: `_TIFFmemcpy(op, bp, ++n)` copies up to 128 bytes from input, but `cc` (remaining valid input bytes) is never checked against `n+1` before the copy. If the raw strip ends with a literal-run header byte but fewer than `n+1` data bytes follow it, up to 127 bytes past the end of `tif_rawdata` are read.

2. **Line 249** — Run-length branch: after reading the run header byte (`cc` decremented to 0), the code unconditionally executes `b = *bp++, cc--` to read the run-data byte without verifying `cc > 0`. When the strip ends on exactly the header byte, one byte is read past the end of `tif_rawdata`.

---

## VULN: PackBitsDecode literal-copy branch heap OOB read (up to 127 bytes)
- **漏洞类别**: memory-safety
- **函数**: PackBitsDecode()
- **行号**: 252-263
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 6.1 (AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted TIFF file
- **外部触发路径**: Application → TIFFOpen() → TIFFReadEncodedStrip() → TIFFFillStrip() → (*tif->tif_decodestrip)() [= PackBitsDecode] → PackBitsDecode(): line 261 _TIFFmemcpy(op, bp, ++n)
- **描述**: 在 PackBitsDecode 的字面量复制分支（else 分支，`n >= 0`），代码在写入输出缓冲区之前正确检查了 `occ < n + 1`（输出边界），但在调用 `_TIFFmemcpy(op, bp, ++n)` 从输入缓冲区读取数据之前，**从未检查**输入剩余字节数 `cc >= n + 1`。`cc` 的值来自 `tif->tif_rawcc`（即 TIFF StripByteCounts 字段，完全由文件控制）。若攻击者构造 strip 的压缩数据以字面量运行头部字节 `0x7E`（n=126，意为复制 127 字节）结尾，但后续实际数据不足 127 字节，则 `_TIFFmemcpy` 将从 `bp` 处读取超出 `tif_rawdata` 分配边界最多 127 字节的堆/mmap 内存。泄露的字节随后被写入解码输出缓冲区（`op`），随解码数据一起返回给调用方。
- **触发条件**: 构造 PACKBITS 压缩的 TIFF 文件，使某条带（strip）的原始压缩数据以字面量运行头部字节（0x00–0x7E）结尾，且该字节之后的实际数据字节数少于头部声明的 `n+1` 个字节（例如 strip 仅剩 1 字节的原始数据，且该字节为 0x7E）。文件需通过 `TIFFReadEncodedStrip`、`TIFFReadScanline` 或 `TIFFReadEncodedTile` 等解码 API 处理。
- **安全影响**: 堆/mmap 越界读取最多 127 字节：(1) 若越界区域为已映射内存，泄露相邻堆块内容（潜在信息泄露，帮助绕过 ASLR）；(2) 若越界区域为未映射内存（strip 数据位于文件映射末尾），触发 SIGSEGV，造成拒绝服务（DoS）。

## VULN: PackBitsDecode run-length branch missing input guard (1-byte heap OOB read)
- **漏洞类别**: memory-safety
- **函数**: PackBitsDecode()
- **行号**: 236-251
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 5.5 (AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted TIFF file
- **外部触发路径**: Application → TIFFOpen() → TIFFReadEncodedStrip() → TIFFFillStrip() → (*tif->tif_decodestrip)() [= PackBitsDecode] → PackBitsDecode(): line 249 `b = *bp++, cc--`
- **描述**: 在 PackBitsDecode 的行程编码（run-length）分支（`n < 0`），外层循环条件 `cc > 0` 保证进入循环体时至少有 1 字节输入；读取运行头部字节后（第 229 行 `n = (long) *bp++, cc--`），`cc` 可能已减至 0。若 `n` 处于范围 [-127, -1]（即非 nop 的行程编码字节），代码在未检查 `cc > 0` 的情况下直接执行第 249 行 `b = *bp++, cc--`，从 `bp` 读取已超出 `tif_rawdata` 合法边界的 1 字节数据。该字节随后被复制（重复 `-n+1` 次）到输出缓冲区。`tsize_t` 为有符号 int32，`cc` 减为 -1 后循环退出，但 OOB 读取已发生。
- **触发条件**: 构造 PACKBITS 压缩的 TIFF 文件，使某条带的原始压缩数据恰好以 1 字节的行程编码头部（任意非 0x80 的值，即字节值在 0x81–0xFF 范围内）结尾，后面没有数据字节跟随。文件需通过解码 API（TIFFReadEncodedStrip / TIFFReadScanline 等）处理。
- **安全影响**: 越界读取 1 字节堆/mmap 内存并将其重复写入解码输出缓冲区（最多 128 次重复），导致 1 字节堆元数据或相邻分配内容泄露到解码数据中；若 strip 位于 mmap 末尾则可能触发 SIGSEGV（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
