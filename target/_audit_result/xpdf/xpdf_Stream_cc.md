Now I have enough context. Let me write the final consolidated report based on the complete analysis of all 6080 lines.

**Summary of findings across the full file:**

- **Batch 1 (1–500)**: Stream base class, ImageStream — overflow guards present and correct.
- **Batch 2 (500–1000)**: StreamPredictor — overflow checks before alloc; `upLeftBuf[gfxColorMaxComps*2+1]` = 65, pixBytes ≤ 64, so `memset(..., pixBytes+1)` is in bounds.
- **Batch 3 (1000–1500)**: ASCIIHex/ASCII85 decoders — no issues.
- **Batch 4 (1500–2000)**: LZWStream — seqBuf[4097], max LZW sequence length ≤ 3840; RunLength buf[128] safe (n ≤ 128); CCITTFax row reads appear bounded.
- **Batch 5 (2000–2500)**: CCITTFax readRow / getTwoDimCode — a0i bounded by loop invariant, codingLine[columns+1] and refLine[columns+3] correctly sized.
- **Batch 6 (2500–3000)**: DCTStream (HAVE_JPEGLIB path — **not compiled** in this build, aconf.h has no HAVE_JPEGLIB); custom DCT begins.
- **Batch 7 (3000–3500)**: readMCURow — rowBuf accesses use `width` as stride, rowBuf allocated with `bufWidth ≥ width`; max offsets stay within bounds.
- **Batch 8 (3500–4000)**: readScan, readDataUnit, readProgressiveDataUnit — dctZigZag[64] access bounded by `if (i < 64)`.
- **Batch 9 (4000–4200)**: readHuffmanTables — **VULNERABILITY FOUND**: `sym` is `Guchar` and wraps at 256. `firstSym[i]` stores pre-wrap cumulative counts. readHuffSym then accesses `tbl->sym[firstSym[codeBits] + code]` where sum can exceed 255 → heap OOB read.
- **Batch 10 (4200–4700)**: Fixed Huffman code tables (static data).
- **Batch 11 (4700–5200)**: FlateStream readSome/startBlock — circular buffer copy logic correct; decompression bomb check present.
- **Batch 12 (5200–5557)**: readDynamicCodes, compHuffmanCodes, getHuffmanCodeWord — bounds checks present; codeLengths[318] properly guarded.
- **Batch 13 (5557–6080)**: Encoder classes (LZWEncoder, RunLengthEncoder, etc.) — encoder paths, not part of PDF decode attack surface for pdftotext.

## VULN: DCTStream Heap OOB Read via Overflowed Huffman Symbol Count
- **漏洞类别**: memory-safety
- **函数**: `DCTStream::readHuffmanTables()` / `DCTStream::readHuffSym()`
- **行号**: 4160–4203 (vulnerability root) / 3807–3813 (OOB dereference site)
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted PDF file with embedded DCT (JPEG) image stream containing a malformed DHT (Define Huffman Table) marker
- **外部触发路径**: `pdftotext input.pdf` → `PDFDoc::displayPage()` → `Gfx::display()` → image rendering → `DCTStream::reset()` → `DCTStream::readHeader()` → `DCTStream::readHuffmanTables()` [root cause] → `DCTStream::prepare()` / `readMCURow()` → `DCTStream::readDataUnit()` → `DCTStream::readHuffSym()` [OOB dereference]
- **描述**: 在 `readHuffmanTables()` 中，局部变量 `sym` 类型为 `Guchar`（无符号 8 位），用于累加各码长的符号数量：`sym = (Guchar)(sym + c)`；当累加超过 255 时发生截断回绕，实际写入 `tbl->sym[]` 的符号数为截断后的值（< 256）。但 `tbl->firstSym[i]` 存储的是回绕前的中间累计值（最大 255），`tbl->numCodes[i]` 存储的是原始字节值（0–255）。随后在 `readHuffSym()` 中执行 `return table->sym[table->firstSym[codeBits] + code]`，其中 `firstSym[codeBits]`（≤ 255）加上 `code`（≤ `numCodes[codeBits]−1`，最大 254）之和可达 509，远超 `sym[256]` 数组的范围，导致堆越界读。`HAVE_JPEGLIB` 在本构建中未定义，该自定义 DCT 解码器完全激活。
- **触发条件**: 构造一个 PDF 文件，其中嵌入 DCT 流（`/Filter /DCTDecode`）。该流的 JPEG 数据中包含 DHT 段（marker `0xFFC4`），设置如下：码长 1 的符号数（numCodes[1]）= 2，码长 2 的符号数（numCodes[2]）= 255。这使 `sym` 从 2 累加至 257 后截断为 1（Guchar 回绕），`firstSym[2]` = 2，`numCodes[2]` = 255。当 JPEG 扫描数据触发一个 2 位码命中（firstCode[2]≤code＜firstCode[2]+255），则执行 `sym[2 + code]`（最大 `sym[256]`），读出 `sym[]` 数组末尾之后的内存（`DCTHuffTable` 结构体中相邻字段或下一个 Huffman 表的数据）。
- **安全影响**: （1）堆内存越界读（最多 253 字节），泄露 `DCTHuffTable` 相邻成员（firstSym/firstCode/numCodes）或其他 Huffman 表的内容，造成信息泄露；（2）读到的垃圾值作为 AC 系数符号参与后续 DCT 解码，输出图像数据损坏；（3）若越界读命中不可访问内存页则导致进程崩溃（DoS）；（4）在 ASLR 较弱或堆布局可预测的环境中，结合进一步漏洞可能构成信息辅助的利用链。

<!-- AUDIT_PROMPT_VERSION: 1 -->
