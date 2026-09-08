Based on my thorough review of the entire JPXStream.cc file (3617 lines), I have confirmed one clear memory-safety vulnerability. Here is my final audit report.

## VULN: Integer overflow in nPrecincts computation leading to heap buffer overflow (or NULL deref)
- **漏洞类别**: memory-safety
- **函数**: JPXStream::readTilePart()
- **行号**: 2050-2063
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow) / CWE-476 (NULL Pointer Dereference)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted PDF file containing a JPX image stream
- **外部触发路径**: `pdftotext input.pdf` → `JPXStream::getChar()` → `JPXStream::decodeImage()` → `JPXStream::readBoxes()` → `JPXStream::readCodestream()` → `JPXStream::readTilePart()` (line 2054)
- **描述**: 在 `readTilePart()` 中，计算每个分辨率级别的预先块（precinct）总数时，对 `(preCol1 - preCol0) * (preRow1 - preRow0)` 做 `Guint` 乘法，没有任何乘法溢出保护（对比同文件 line 982–983 的 `nXTiles * nYTiles` 检查和 line 1978–1979 的 `tileComp->w * tileComp->h` 检查，均有 `INT_MAX / n` 保护，而 `nPrecincts` 处无保护）。计算结果直接传给 `gmallocn(nPrecincts, sizeof(JPXPrecinct))`。当乘积溢出 32 位回绕到 0 时，`gmallocn(0, …)` 返回 NULL，随后 `precinct = resLevel->precincts`（为 NULL），循环体 `precinct->subbands = gmallocn(nSBs, …)` 即刻 NULL 指针解引用（DoS）。当乘积回绕到较小非零值 K 时，只分配 K 个 `JPXPrecinct`，而后续双重循环仍按真实计数（最多 `2^64/sizeof(Guint)` 量级）迭代，对已分配缓冲区尾端之后的堆内存进行越界写（heap buffer overflow，可能达到 RCE）。
- **触发条件**: 构造含 JPX 图像的 PDF，在 JPX 码流的 SIZ 标记段中设置大幅面尺寸（如 xSize = ySize = 131072），在 COD 标记段中将 `style & 0x01` 置位并对 r=0 输出预先块大小字节 `0x00`（precinctWidth=0, precinctHeight=0，此处验证逻辑仅限 r>0，r=0 无检查）。对于 r=0 时 `resLevel->x1 = ceil(xSize / 2^nDecompLevels)`，当乘积 `(x1−x0)×(y1−y0)` 发生整数溢出即可触发。
- **安全影响**: 最坏情况：堆溢出可覆盖相邻堆元数据或函数指针，配合信息泄露技术实现远程代码执行（RCE）；最轻情况：NULL 指针解引用导致进程崩溃（DoS）。任意攻击者只需向用户发送恶意 PDF，在目标机器执行 `pdftotext` 即可触发。

<!-- AUDIT_PROMPT_VERSION: 1 -->
