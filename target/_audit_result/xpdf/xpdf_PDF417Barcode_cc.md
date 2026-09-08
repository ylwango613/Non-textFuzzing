## VULN: Stack Buffer Overflow in makeErrorCorrectionCodewords via Unchecked errorCorrectionLevel (local e[] array)
- **漏洞类别**: memory-safety
- **函数**: `makeErrorCorrectionCodewords()` / root cause in `XFAScanner.cc` (no bounds check)
- **行号**: 1827-1851 (`makeErrorCorrectionCodewords`); XFAScanner.cc:578-580 (unchecked read)
- **CWE**: CWE-121 (Stack-based Buffer Overflow)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted PDF file
- **外部触发路径**: PDF (XFA form) → `XFAScanner::parseBarcodeElement()` reads `errorCorrectionLevel` from XML attribute via `atoi()` (XFAScanner.cc:580, no bounds check) → stored in `XFAFieldBarcodeInfo::errorCorrectionLevel` → `AcroForm.cc:2961` calls `drawPDF417Barcode(..., barcodeInfo->errorCorrectionLevel, ...)` → `drawPDF417Barcode()` calls `makeErrorCorrectionCodewords(errorCorrectionLevel, codewords, length)` (line 1383) → stack overflow
- **描述**: `makeErrorCorrectionCodewords()` declares `int e[1 << (maxErrorCorrectionLevel + 1)]` (i.e., `e[512]`) on the stack, then computes `k = 1 << (errorCorrectionLevel + 1)`. Because `errorCorrectionLevel` comes from an untrusted XFA XML attribute and is never validated to be ≤ `maxErrorCorrectionLevel (8)`, an attacker can set it to 9 (k=1024) or 10 (k=2048). The initialization loop `for (int i = 0; i < k; ++i) { e[i] = 0; }` immediately writes up to 2048 ints into a 512-element stack array, overwriting adjacent stack frames with zeros/attacker-influenced data. Confirmed: with level=9 the array is overflowed by 512 ints; with level=10 by 1536 ints.
- **触发条件**: PDF 包含 XFA 表单，其中 barcode 元素的 `errorCorrectionLevel` 属性被设置为 ≥ 9 的值（例如 `errorCorrectionLevel="9"`），并且 barcode 类型为 `pdf417`，且字段尺寸满足 nRows ≤ 90 的约束（level=9 时 nRows 最小 36，level=10 时最小 70，均满足 ≤ 90）。
- **安全影响**: 覆盖栈帧上的返回地址和局部变量，在无地址随机化保护时可实现 RCE；在有保护的情况下也可稳定触发进程崩溃（DoS）。

## VULN: Stack Buffer Overflow in drawPDF417Barcode via Unchecked errorCorrectionLevel (caller codewords[] array)
- **漏洞类别**: memory-safety
- **函数**: `drawPDF417Barcode()` caller stack frame, overwritten by `makeErrorCorrectionCodewords()`
- **行号**: 1327 (`codewords` declaration), 1846-1850 (OOB write back into caller's buffer)
- **CWE**: CWE-121 (Stack-based Buffer Overflow)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted PDF file
- **外部触发路径**: 同上，同一根因不同崩溃点 — `makeErrorCorrectionCodewords()` 在写回阶段 `codewords[j++] = ee;`（行 1849）将 k 个 int 写入从索引 `length` 开始的 `codewords[]`，该数组在 `drawPDF417Barcode()` 中声明为 `int codewords[maxDataCodewords + maxErrorCorrectionCodewords] = codewords[1440]`（行 1327）
- **描述**: `makeErrorCorrectionCodewords()` 最终将 `k` 个纠错码字写回 `codewords[length .. length+k-1]`。当 `errorCorrectionLevel=9`（k=1024）且攻击者将 nRows 调整为 65、nCols=30 时，length=926，写入范围为 codewords[926..1949]，超出 1440 元素缓冲区上界 510 个 int；当 level=10（k=2048）、nRows=70 时，写入范围为 codewords[52..2099]，超出 660 个 int。两者均通过了 `length ≤ maxDataCodewords` 和 `nRows ≤ 90` 的检查，安全地到达写入点。
- **触发条件**: 同 VULN 1，需要额外通过控制 `fieldWidth`/`fieldHeight`/`moduleWidth`/`moduleHeight` 使 nRows 取较大值（如 65）以扩大 `nPadCodewords` 和 `length`，从而使写入范围超出 1440。
- **安全影响**: `drawPDF417Barcode()` 栈帧上的 `codewords[1440]` 之后的返回地址或局部变量被覆盖，与 VULN 1 联合利用可构成可靠的栈溢出 RCE 原语。

## VULN: Out-of-Bounds Pointer Array Read/Deref via errorCorrectionCoeff[errorCorrectionLevel]
- **漏洞类别**: memory-safety
- **函数**: `makeErrorCorrectionCodewords()`
- **行号**: 1838, 1842
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted PDF file
- **外部触发路径**: XFA barcode `errorCorrectionLevel` 属性（atoi，无校验）→ `drawPDF417Barcode()` → `makeErrorCorrectionCodewords(errorCorrectionLevel, ...)` → `errorCorrectionCoeff[errorCorrectionLevel][j]`（行 1838）
- **描述**: `errorCorrectionCoeff` 被声明为 `static int *errorCorrectionCoeff[maxErrorCorrectionLevel + 1]`，共 9 个 `int*` 指针（合法下标 0-8）。当 `errorCorrectionLevel ≥ 9` 时，`errorCorrectionCoeff[errorCorrectionLevel]` 读取数组边界之外的内存（该区域紧接静态数据段中的 `startPattern`、`stopPattern` 等），将其解释为 `int*` 指针并解引用（`[j]` 下标）。这是二次 OOB 读取，可能泄露进程内存地址或造成崩溃。实际执行中此访问发生在 VULN 1 的栈溢出之后（栈初始化循环先运行），但作为独立的内存安全缺陷单独报告。
- **触发条件**: 同 VULN 1，`errorCorrectionLevel ≥ 9`。
- **安全影响**: 进程崩溃（DoS）或泄露静态/堆内存内容，辅助 ASLR 绕过。

<!-- AUDIT_PROMPT_VERSION: 1 -->
