## VULN: Stack Buffer Overflow via Unchecked errorCorrectionLevel in makeErrorCorrectionCodewords
- **漏洞类别**: memory-safety
- **函数**: makeErrorCorrectionCodewords()
- **行号**: 1827-1851
- **CWE**: CWE-121 (Stack-based Buffer Overflow)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted PDF file (XFA barcode element with errorCorrectionLevel attribute)
- **外部触发路径**: pdftotext → AcroForm::drawBarcodeField() → drawPDF417Barcode() → makeErrorCorrectionCodewords()；errorCorrectionLevel 通过 XFAScanner.cc:580 `atoi(attr->getValue())` 不加边界检查地从 PDF XFA 属性读入，经 AcroForm.cc:2963 传入 drawPDF417Barcode()，再于 PDF417Barcode.cc:1383 传入 makeErrorCorrectionCodewords()
- **描述**: `makeErrorCorrectionCodewords()` 在栈上声明了固定大小缓冲区 `int e[1 << (maxErrorCorrectionLevel + 1)]`（即 e[512]，PDF417Barcode.cc:1829）。函数内部用文件控制的 `errorCorrectionLevel` 计算循环上界 `k = 1 << (errorCorrectionLevel + 1)`（第 1830 行）。随后 `for (int i = 0; i < k; ++i) { e[i] = 0; }`（第 1831-1833 行）在 k > 512 时越界写栈，覆盖相邻局部变量、保存的帧指针及返回地址。`errorCorrectionLevel` 在整个调用链中均无范围校验——XFAScanner.cc:580 仅做 `atoi()`，drawPDF417Barcode() 亦无校验（maxErrorCorrectionLevel=8，errorCorrectionLevel=9 即令 k=1024，溢出 2048 字节栈空间）。
- **触发条件**: 构造一个包含 XFA 表单的 PDF，其中 barcode 元素的 `errorCorrectionLevel` 属性值 ≥ 9（例如 `errorCorrectionLevel="9"`），barcode 类型为 "pdf417"，并提供合法的 moduleWidth/moduleHeight 使 drawPDF417Barcode 不提前返回。
- **安全影响**: 攻击者控制的 errorCorrectionLevel 值触发 2KB 以上的栈溢出，覆盖函数返回地址，在现代编译器/系统开启 SSP 的情况下至少可导致崩溃（DoS），在缺少栈保护的构建配置下可实现任意代码执行（RCE）。

## VULN: OOB Read of errorCorrectionCoeff Global Pointer Table via Unchecked errorCorrectionLevel
- **漏洞类别**: memory-safety
- **函数**: makeErrorCorrectionCodewords()
- **行号**: 1838, 1842
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted PDF file (XFA barcode element with errorCorrectionLevel attribute)
- **外部触发路径**: pdftotext → AcroForm::drawBarcodeField() → drawPDF417Barcode() → makeErrorCorrectionCodewords()；同 VULN-1 的 errorCorrectionLevel 传递路径
- **描述**: `errorCorrectionCoeff` 是包含 9 个指针的全局数组（索引 0–8，PDF417Barcode.cc:340），对应 9 级纠错系数表。在 makeErrorCorrectionCodewords() 内层循环（第 1838 行：`errorCorrectionCoeff[errorCorrectionLevel][j]`，第 1842 行：`errorCorrectionCoeff[errorCorrectionLevel][0]`），当攻击者设置 errorCorrectionLevel ≥ 9 时，数组下标越界，读取全局段相邻内存（解引用野指针）。该越界读可能导致信息泄露（读取相邻全局数据）或在解引用无效指针时崩溃。
- **触发条件**: 同 VULN-1，errorCorrectionLevel ≥ 9 即可触发；在栈溢出（VULN-1）未立即终止进程的情况下，执行流继续到内层循环，触发 OOB 读。
- **安全影响**: 泄露全局内存段相邻数据（潜在信息泄露），或因访问非法指针导致进程崩溃（DoS）。

## VULN: OOB Read of patterns[] Array via Large errorCorrectionLevel in drawBarcode
- **漏洞类别**: memory-safety
- **函数**: drawBarcode()
- **行号**: 1881, 1886, 1891, 1897
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted PDF file (XFA barcode element with errorCorrectionLevel attribute)
- **外部触发路径**: pdftotext → AcroForm::drawBarcodeField() → drawPDF417Barcode() → drawBarcode()；errorCorrectionLevel 同 VULN-1 路径注入，在 makeErrorCorrectionCodewords 之后 drawBarcode 被调用（PDF417Barcode.cc:1395）
- **描述**: `patterns` 数组声明为 `static char patterns[929][3][8]`（第 361 行）。drawBarcode 在 cluster=1 时计算 `left = 30 * (row / 3) + (errorCorrectionLevel * 3) + (nRows - 1) % 3`（第 1881 行），cluster=2 时计算 `right`（第 1886 行），随后以 `patterns[left][cluster]`（第 1891 行）和 `patterns[right][cluster]`（第 1897 行）下标访问该数组。当 errorCorrectionLevel ≥ 19 且 nRows=90（最大值）、row=89 时：left = 870 + 57 + 2 = 929，恰好超出 patterns[] 的合法范围（0–928），读取相邻全局静态数据段内容并将其当作 pattern 字节使用，传递给 drawPattern()，继而向 appearBuf 写入任意内容。
- **触发条件**: 构造 PDF 中 `errorCorrectionLevel` ≥ 19，并使 nRows 达到最大值（90 行），row 索引为 89 时即可触发越界读。
- **安全影响**: 读取相邻全局内存内容（潜在信息泄露），并将其内容写入输出缓冲区 appearBuf（潜在数据泄露），或因访问非法地址导致崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
