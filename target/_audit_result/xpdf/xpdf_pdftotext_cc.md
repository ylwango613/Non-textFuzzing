## VULN: DCTStream 内置 Huffman 表 firstSym 截断引发 sym[] 堆越界读
- **漏洞类别**: memory-safety
- **函数**: DCTStream::readHuffmanTables() / DCTStream::readHuffSym()
- **行号**: 4160-4203 / 3791-3817
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 5.3 (CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted PDF file (with malformed JPEG DHT segment embedded in DCTDecode stream)
- **外部触发路径**: pdftotext main() → PDFDoc::displayPages() → Page::display() → Gfx::display() → image rendering → DCTStream::readHeader() → DCTStream::readHuffmanTables() [builds bogus firstSym] → DCTStream::readScan() → DCTStream::readHuffSym() [OOB read from sym[]]
- **描述**: 在 `#ifndef HAVE_JPEGLIB` 编译路径下，`readHuffmanTables()`（Stream.cc:4188-4196）使用 **`Guchar`（8 位无符号整数）**累加各比特长度的 Huffman 符号数量：`sym = (Guchar)(sym + c)`。当精心构造的 JPEG DHT 段使各码长符号数之和超过 255 时，`sym` 发生截断回绕，导致 `tbl->firstSym[i]`（同为 `Guchar` 类型，Stream.h:655）存储了错误的偏移值。在后续 `readHuffSym()`（Stream.cc:3812）执行 `table->sym[table->firstSym[codeBits] + code]` 时，若 `firstSym[codeBits]`（如 200）加上有效 `code` 偏移（如 0–99）超过 `sym[256]` 数组边界，则产生堆上越界读取，访问 `sym[256..299]` 范围外的相邻堆内存。
- **触发条件**: (1) xpdf 编译时 `HAVE_JPEGLIB` 未定义（不链接 libjpeg，使用内置 DCT 解码器）；(2) PDF 内嵌包含 DCTDecode 流，其中 JPEG DHT 段各码长符号数总和 > 255（违反 JPEG 规范但解析代码未拒绝）。具体示例：DHT 段设置 1-bit 码 200 个 + 2-bit 码 100 个，使得 `firstSym[2] = 200`、`numCodes[2] = 100`，解码时访问 `sym[200..299]`，越界 44 字节。
- **安全影响**: 堆越界读（OOB Read）——读取 `DCTHuffTable.sym[256]` 数组边界之后最多数十字节的相邻堆内容，可能导致进程崩溃（DoS）或将堆布局信息/敏感数据泄漏到 Huffman 解码输出流中，进而辅助后续更高危漏洞利用。

<!-- AUDIT_PROMPT_VERSION: 1 -->
