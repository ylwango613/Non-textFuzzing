Based on my thorough analysis of Gfx.h and all related implementations (Gfx.cc, GfxState.h, GfxState.cc), I have identified one confirmed memory-safety vulnerability.

## VULN: Heap Buffer Overflow in GfxICCBasedColorSpace Range Array Parsing (OOB Write)
- **漏洞类别**: memory-safety
- **函数**: GfxICCBasedColorSpace::parse() / triggered via Gfx::opSetFillColorSpace() / Gfx::opSetStrokeColorSpace()
- **行号**: GfxState.cc:964-973 (OOB write); GfxState.h:452-453 (fixed-size victim arrays)
- **CWE**: CWE-122 (Heap-Based Buffer Overflow)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted PDF file
- **外部触发路径**: `pdftotext malicious.pdf` → `PDFDoc::displayPage()` → `Gfx::display()` → `Gfx::go()` → `Gfx::execOp()` → `Gfx::opSetFillColorSpace()` (PDF `cs` operator) or `Gfx::opSetStrokeColorSpace()` (PDF `CS` operator) → `GfxColorSpace::parse()` → `GfxICCBasedColorSpace::parse()` → OOB write to `cs->rangeMin[i]` / `cs->rangeMax[i]`
- **描述**: `GfxICCBasedColorSpace` 结构体中 `rangeMin[4]` 和 `rangeMax[4]` 固定声明为 4 个元素（GfxState.h:452-453）。在 `GfxICCBasedColorSpace::parse()`（GfxState.cc:964-973）中，若 ICCBased 色彩空间的 `N` 字段大于 4 且提供了匹配的 `Alternate`（如 DeviceN 含 N 个分量，可达 32），则 `nCompsA` 不会被截断至 4，随后 Range 数组解析循环 `for (i = 0; i < nCompsA; ++i) { cs->rangeMin[i] = ...; cs->rangeMax[i] = ...; }` 对 `i >= 4` 的访问越过结构体边界，向堆上相邻内存写入攻击者可控的浮点数值（每个分量写 8 字节，N=32 时共越界写 (32-4)×8×2 = 448 字节），破坏堆元数据或相邻对象。`getDefaultColor()` 随后也以同样的 `nComps` 读取 `rangeMin[i]` / `rangeMax[i]`，构成 OOB 读。
- **触发条件**: 攻击者构造包含以下内容的 PDF 文件：① ICCBased 色彩空间，N 字段 > 4（如 N=5 或 N=32）；② 其 Alternate 为 DeviceN 且包含相同数量的分量名称（保证 `altA->getNComps() == nCompsA`，从而绕过修正逻辑）；③ Range 数组长度精确等于 `2 * N`，元素为任意数值。将该色彩空间设置为页面内容流的填充/描边色彩空间即可触发。
- **安全影响**: 攻击者向堆上越界写入可控值，可破坏 `GfxICCBasedColorSpace` 对象之后紧邻的堆数据（包括 `iccProfileStream` Ref 结构及后续堆块头部）。在有利的堆布局下，可进一步实现任意地址写，最终导致远程代码执行（RCE）；最坏情况下至少造成进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
