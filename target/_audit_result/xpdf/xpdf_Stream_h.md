Based on my comprehensive analysis of all 1076 lines of Stream.h plus the corresponding Stream.cc implementation, I have identified one confirmed memory safety vulnerability.

**Batch 1 analysis (lines 0-600):** Examined CCITTFaxStream, LZWStream, RunLengthStream, ImageStream, StreamPredictor, and FileStream. The CCITTFax `addPixels`/`addPixelsNeg` functions (lines 1760-1800 in Stream.cc) have no upper-bound guard on `a0i` before incrementing and writing to `codingLine`.

**Batch 2 analysis (lines 600-1076):** Examined FlateStream, DCTStream, BufStream. FlateStream uses ring-buffer masking (`& flateMask`) for all `buf[]` accesses — safe. DCTStream `frameBuf`/`rowBuf` allocations include overflow checks and bounded writes — safe. LZW `seqBuf[4097]` and `table[4097]` — max `seqLength` bounded by code depth (~3840) — safe.

**Root cause of CCITTFax OOB:** `codingLine` is allocated as `columns + 1` ints (comment at line 1581 confirms this). In the 2D horizontal-mode decode path (`twoDimHoriz`, line 1860–1862), two consecutive `addPixels` calls occur per loop iteration; each can increment `a0i`. After the first call brings `a0i` to `columns` with `codingLine[columns] < columns`, the guard `if (codingLine[a0i] < columns)` is true, and the second `addPixels` call with the parity condition `(columns & 1) ^ (blackPixels ^ 1)` being true increments `a0i` to `columns + 1` and writes `codingLine[columns + 1]` — one element past the heap allocation. Same OOB is reachable across two successive `twoDimVert*` iterations.

## VULN: CCITTFaxStream addPixels heap buffer overflow via 2D horizontal mode
- **漏洞类别**: memory-safety
- **函数**: `CCITTFaxStream::addPixels()`, `CCITTFaxStream::addPixelsNeg()`, `CCITTFaxStream::readRow()`
- **行号**: 1760-1801 (addPixels/addPixelsNeg), 1860-1862 (twoDimHoriz in readRow), 1584 (codingLine allocation)
- **CWE**: CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted PDF file
- **外部触发路径**: `pdftotext malicious.pdf` → `PDFDoc::displayPages()` → `Gfx::drawImage()` → `Stream::addFilters()` → `CCITTFaxStream` construction (with K≠0, Columns=N from PDF dict) → `CCITTFaxStream::getChar()` → `CCITTFaxStream::readRow()` → `twoDimHoriz` case → `addPixels(…, blackPixels)` then `addPixels(…, blackPixels^1)` → heap OOB write to `codingLine[columns+1]`
- **描述**: `codingLine` 在构造函数中以 `gmallocn(columns + 1, sizeof(int))` 分配，合法索引为 `0..columns`。在 2D 水平编码模式（`twoDimHoriz`）分支中，一次 while 循环迭代内连续调用两次 `addPixels`。`addPixels` 内部在条件 `(a0i & 1) ^ blackPixels` 成立时执行 `++a0i`，之后写 `codingLine[a0i]`，但没有任何对 `a0i` 上界的校验。当第一次调用将 `a0i` 从 `columns-1` 递增至 `columns` 且写入 `codingLine[columns]` 的值仍小于 `columns` 时，`if (codingLine[a0i] < columns)` 检查通过，第二次 `addPixels` 调用又将 `a0i` 从 `columns` 递增至 `columns+1`，继而写 `codingLine[columns+1]`，越出堆分配边界 4 字节。
- **触发条件**: 攻击者构造含 CCITTFax 过滤器的 PDF（`/Filter /CCITTFaxDecode`，`/K` 不为零以启用 2D 编码，`/Columns N`），并精心布置 CCITT 码字序列：先用足够多的变色段填充 `codingLine` 至 `a0i = columns-1`，再插入一个水平模式码（`H` code），令第一段 `code1` 写入 `codingLine[columns] < columns`，第二段 `code2 > 0`，且 `(columns & 1) ^ (blackPixels ^ 1)` 为真。
- **安全影响**: 4 字节堆越界写（写入值由攻击者通过 `code2` 和 `a1` 控制），破坏紧邻 `codingLine` 之后的堆内存（通常为 `refLine` 分配的起始字段或堆元数据 chunk-size 字段）。可进一步引发受控堆元数据破坏或后续对 `refLine` 越界访问，最坏情况下可导致任意代码执行（RCE）；可靠触发时至少造成崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
