Now I have all the information I need for the final report. Based on thorough analysis of AcroForm.h and AcroForm.cc:

**Bug 1**: `getFont()` uses `tfPos+2`/`tfPos+3` instead of `tmPos+2`/`tmPos+3` (lines 1015–1016). Since `GList::get()` has no bounds check (`void *get(int i) { return data[i]; }`), when a DA string has `Tm` before `Tf` (Tf as last operator), `tfPos+3 == daToks->getLength()` is OOB. Only reachable via HTMLGen.cc (pdftohtml), not pdftotext directly.

**Bug 2**: `drawBarcode()` code128B checksum: `checksum += (i + 1) * c` (line 2946) uses signed int. With ~9,000+ printable characters as barcode value, accumulated sum overflows INT_MAX. Then `c = checksum % 103` (line 2935) becomes negative (signed modulo in C), and `code128Data[c]` (line 2951) with `c < 0` is OOB read below the static array. Reachable from pdftotext when XFA is enabled and barcode fields with code128B type are present.

## VULN: getFont() OOB Heap Read via Wrong Token Index in DA String Handling
- **漏洞类别**: memory-safety
- **函数**: AcroFormField::getFont()
- **行号**: 1013-1017
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:L)
- **严重程度**: Medium
- **攻击向量**: crafted PDF file
- **外部触发路径**: pdftohtml → PDFDoc::displayPages → AcroForm::draw → AcroFormField::draw → drawAnnot → drawNewAppearance → [none; actually via] HTMLGen.cc:712: field->getFont(&fontID, &fontSize) → AcroFormField::getFont()
- **描述**: `getFont()` 在检测到 Tm 操作符（`tmPos >= 0`）后，本应读取 `daToks->get(tmPos + 2)` 和 `daToks->get(tmPos + 3)` 来获取 Tm 矩阵中 m2/m3 分量，但代码错误地使用了 `daToks->get(tfPos + 2)` 和 `daToks->get(tfPos + 3)`。当 DA 字符串中 Tm 出现在 Tf 之前（如 `1 0 0 1 10 20 Tm /F1 12 Tf`），Tf 为最后一个 token（索引 N-1），则 `tfPos = N-3`，`tfPos + 3 = N` 超出 `daToks`（长度 N）的合法范围。`GList::get()` 不做边界检查（实现为 `return data[i]`），直接访问越界堆内存，将读到任意指针并将其解释为 `GString*` 进行 `getCString()` 调用，引发堆越界读。
- **触发条件**: 攻击者构造 PDF，令 AcroForm 字段的 DA 字符串中 Tm 操作符出现在 Tf 操作符之前，且 Tf 及其参数恰好占据 token 列表末尾三个位置（例如 `1 0 0 1 10 20 Tm /F1 12 Tf`）。通过 pdftohtml 处理该 PDF。
- **安全影响**: 越界读取堆内存中相邻对象数据，最坏情况下泄露堆指针（ASLR 绕过信息）或触发崩溃（DoS）。结合其他漏洞可能升级为 RCE。

## VULN: drawBarcode() Code128B Signed Integer Overflow Leading to OOB Static Array Read
- **漏洞类别**: memory-safety
- **函数**: AcroFormField::drawBarcode()
- **行号**: 2926-2952
- **CWE**: CWE-190 (Integer Overflow) → CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted PDF file (with XFA barcode field)
- **外部触发路径**: pdftotext → PDFDoc::displayPage → Gfx::display → AcroForm::draw → AcroFormField::draw → drawAnnot → drawNewAppearance（当 needAppearances=true 或 xfaField->getValue() 非空）→ drawBarcode（当 barcodeType=="code128B"）
- **描述**: `drawBarcode()` 在处理 code128B 条形码时，以有符号 `int` 类型累积校验和：`checksum += (i + 1) * c`（第 2946 行），其中 `i` 从 0 到 `value2->getLength()-1`，`c` 最大为 95（ASCII '~' 减去 32）。当 value2 长度约 ≥ 9,220 个字符（所有字符取最大值时：`95 * n*(n+1)/2 > INT_MAX`）时，`checksum` 发生有符号整数溢出（未定义行为，在 x86 上向下溢出为负数）。随后第 2935 行 `c = checksum % 103` 产生负值（C 语言有符号取模规则），第 2951 行 `code128Data[c][j]`（c < 0）对静态数组执行负索引越界读，读取 code128Data 数组前方的静态数据段内存。
- **触发条件**: 攻击者构造包含 XFA 静态表单的 PDF 文件，表单中含有 barcodeType 为 "code128B" 的条形码字段，字段值（V 字段）长度超过约 9,220 个可打印 ASCII 字符。xpdf 构建时需启用 XFA 支持（`enableXFA=yes`）。
- **安全影响**: 越界读取条形码数据表之前的静态内存，导致程序将读到的随机数据作为条形码宽度值使用，最坏情况引发崩溃（SIGSEGV，DoS）或内存信息泄露（data/BSS 段内容）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
