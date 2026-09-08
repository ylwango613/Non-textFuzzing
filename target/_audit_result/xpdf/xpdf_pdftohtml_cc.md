I've now fully analyzed pdftohtml.cc and its core dependency HTMLGen.cc. Let me compile the final findings.

**Batch 1 analysis (pdftohtml.cc lines 1–424):** The main() function is a thin CLI wrapper — no direct buffer manipulations. All attacker-controlled input flows into PDFDoc/HTMLGen.

**Batch 2 analysis (HTMLGen.cc lines 1–645, convertPage):** Found a confirmed off-by-one in the form-field background-erase region at line 464. The `urxI` clamp uses `>=` (correct) but the `llyI` clamp uses `>` instead of `>=`. When `llyI == bitmap->getHeight()` exactly, the loop iterates one extra row and `memset` writes up to `width×3` bytes past the heap allocation.

**Batch 3 analysis (HTMLGen.cc lines 645–1192, remaining functions):** No additional memory safety issues — GString dynamically resizes, substFonts[i] with i ≤ 11 stays in bounds, parseArgs uses bounded strncpy, appendUTF8 properly bounds-checks all Unicode ranges.

## VULN: Off-by-One Heap OOB Write in Form-Field Background-Erase (HTMLGen.cc:464)
- **漏洞类别**: memory-safety
- **函数**: HTMLGen::convertPage()
- **行号**: 450–473 (关键缺陷在第 464 行)
- **CWE**: CWE-122 (Heap-based Buffer Overflow) / CWE-193 (Off-by-One Error)
- **CVSS v3.1**: 7.5 (AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted PDF file with malicious AcroForm field Rect coordinates
- **外部触发路径**: `pdftohtml -formfields crafted.pdf outdir` → `main()` (pdftohtml.cc:263) → `HTMLGen::convertPage()` (HTMLGen.cc:373) → AcroForm field loop (HTMLGen.cc:431–483) → bitmap erase block (HTMLGen.cc:450–473)
- **描述**: 在 `convertPage()` 处理 `-formfields` 模式时，代码将表单字段 BBox 坐标转换为位图像素坐标，并通过 `llyI += (int)(backgroundResolution * vStretch / 20)` 添加额外偏移。随后对 `llyI` 的越界检查条件为 `if (llyI > bitmap->getHeight())` (第 464 行)，应为 `>= bitmap->getHeight()`（与同函数中对 `urxI` 使用的 `>= bitmap->getWidth()` 一致）。当精心构造的表单字段坐标使 `llyI` 恰好等于 `bitmap->getHeight()` 时，该检查不触发截断，`for (y = uryI; y <= llyI; ++y)` 循环多执行一次，`pix` 指向 `getDataPtr() + bitmap->getHeight() * rowSize`——即超出堆分配末尾整整一行，`memset(pix, 0xff, (urxI - llxI + 1) * 3)` 对该越界地址写入最多 `bitmap->getWidth() * 3` 字节（典型值：150 DPI Letter 页约 5100 字节）。
- **触发条件**: 攻击者构造一个包含 AcroForm 字段的 PDF，其中页面 MediaBox 高度 H points 和字段 Rect 底边坐标 `lly_pdf` 满足：`(int)((H - lly_pdf) * backgroundResolution * vStretch / 72 + 0.5) + (int)(backgroundResolution * vStretch / 20) == bitmap->getHeight()`。例如，默认 150 DPI、vStretch=1、Letter 页 (H=792 pt)：令 `lly_pdf ≈ 4 pt`（字段底边离页面底部约 4 pt），即可精确满足 `llyI == 1650 == bitmap->getHeight()`。用户需以 `pdftohtml -formfields crafted.pdf outdir` 调用（-formfields 是合法的文档转换功能）。
- **安全影响**: 在 `SplashBitmap` 分配块末尾之后写入最多数千字节（全部为 0xFF），可覆盖 malloc 管理元数据或相邻堆对象，在现代堆分配器上可利用以实现任意代码执行 (RCE)；即使无法稳定利用，也必然触发崩溃 (DoS)。

<!-- AUDIT_PROMPT_VERSION: 1 -->
