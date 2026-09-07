## VULN: GfxICCBasedColorSpace Range Array Heap Buffer Overflow
- **漏洞类别**: memory-safety
- **函数**: GfxICCBasedColorSpace::parse()
- **行号**: 963-978
- **CWE**: CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted PDF file
- **外部触发路径**: pdftotext → PDFDoc::displayPages → Gfx::display → Gfx::execOp (cs/CS/scn/SCN operators) → GfxColorSpace::parse → GfxICCBasedColorSpace::parse
- **描述**: `GfxICCBasedColorSpace` 的私有字段 `rangeMin[4]` 和 `rangeMax[4]` 均为固定 4 元素的 `double` 数组（GfxState.h:452-453）。在 `parse()` 函数第 963-978 行中，当 PDF 提供了 `Alternate` 颜色空间（如 DeviceN，可合法拥有最多 32 个分量）时，`nCompsA` 会被设置为该替代色彩空间的分量数，而无任何 `<= 4` 的上界校验。随后第 964-966 行的 `if` 条件仅检查 Range 数组长度是否等于 `2 * nCompsA`（攻击者完全可控），之后循环写入 `cs->rangeMin[i]` 和 `cs->rangeMax[i]`（`i < nCompsA`）：当 `i >= 4` 时 `rangeMin[i]` 写入 `rangeMax` 区域（in-object 覆盖）；当 `i >= 5` 时 `rangeMax[i]` 写入 `iccProfileStream` 字段之后的堆内存，造成堆越界写入（每个 `double` 为 8 字节，攻击者可控），最多可溢出约 `(nCompsA - 4) * 8 * 2 - 8` 字节（nCompsA 最大 32 时约 208 字节）。
- **触发条件**: 攻击者构造一个含有如下结构的 PDF 文件：ICCBased 颜色空间流的字典中 `/N` 为 6 或更大、`/Alternate` 为一个具有相同分量数的 DeviceN 色彩空间、`/Range` 数组具有恰好 `2 * N` 个元素。当 pdftotext 解析该 PDF 并遇到使用此色彩空间的颜色操作（cs/CS/scn/SCN）时，漏洞即被触发。
- **安全影响**: 堆越界写入，写入内容（双精度浮点数）由 PDF 中的 Range 数组完全控制；可破坏相邻堆对象（如 vtable 指针、其他 GfxColorSpace/Function 对象），在有利的堆布局下可实现任意代码执行（RCE）；最坏情况可导致攻击者在目标用户权限下执行任意代码，或导致进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
