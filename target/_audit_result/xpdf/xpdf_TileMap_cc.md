Now I have all the context needed. Let me produce the final audit report.

**Analysis summary:**

**Batch 1 (lines 1–500):** `getTileList()` accesses `pageDPI[page-1]`, `pageW[page-1]`, `pageH[page-1]`, `tileW[page-1]`, `tileH[page-1]` using `state->getScrollPage()` without validating that `scrollPage` is in `[1, numPages]`. Arrays are allocated with `numPages` elements.

**Batch 2 (lines 501–900):** `getScrollLimits()` at line 501 similarly uses `getScrollPage()-1` without validation. `getPageTopY(page)` (line 944) and `getPageBottomY(page)` (lines 961/964) directly index `pageY[page-1]` and `pageH[page-1]` with no range check on `page`.

**Batch 3 (lines 900–1216):** `getPageLeftX(page)` and `getPageRightX(page)` access `pageW[page-1]`/`pageX[page-1]` without checking `page`. `getPageBoxWidth(page)` (line 1211) and `getPageBoxHeight(page)` (line 1215) access heap arrays `pageBoxW[page-1]` and `pageBoxH[page-1]` with **zero bounds checking** — no guard at all.

**Cross-reference with PDFCore.cc callers:** Confirmed via grep that `getPageTopY(page)`, `getPageLeftX(page)`, and `getPageBoxWidth(page)` are called in `PDFCore.cc` with `page` values derived from PDF link destinations (`case destXYZ:`, `case destFitH:` etc. at lines 302–348) — a PDF-attacker-controlled value.

**Batch 4 (lines 1216–1687):** `updatePageParams()`, `updateContinuousModeParams()`, `findContinuousPage()` etc. are internally consistent — `gmallocn` has overflow checks, tile sizes are kept ≥1. The aliased `pageX = pageY` allocation is intentional (only one mode active at a time, freed correctly via `clearContinuousModeParams`). No additional memory safety issues found.

---

## VULN: OOB Heap Read in getPageBoxWidth/getPageBoxHeight via Crafted PDF Link Destination
- **漏洞类别**: memory-safety
- **函数**: `TileMap::getPageBoxWidth()`, `TileMap::getPageBoxHeight()`
- **行号**: 1210-1216
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 6.1 (AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted PDF file
- **外部触发路径**: `main()` → `PDFDoc::open()` → xpdf viewer renders PDF → 用户/自动触发 PDF 内 link/dest action → `PDFCore::displayDest()` (PDFCore.cc:302-348) → `tileMap->getPageBoxWidth(page)` / `tileMap->getPageBoxHeight(page)` → `pageBoxW[page - 1]` 越界读
- **描述**: `getPageBoxWidth(int page)` 和 `getPageBoxHeight(int page)` 直接返回 `pageBoxW[page - 1]` 和 `pageBoxH[page - 1]`，完全没有对 `page` 的范围校验。`pageBoxW`/`pageBoxH` 是在 `docChanged()` 中通过 `greallocn(pageBoxW, nPages, sizeof(double))` 分配的堆数组，长度恰好为 `nPages`。当 `page = 0` 时，`page - 1 = -1`，读取数组起始地址之前的堆内存；当 `page > nPages` 时，读取数组末尾之后的堆内存。这两种情况均为堆越界读（heap out-of-bounds read）。PDFCore.cc 的 `displayDest()` 函数在处理 `/Dest` link action（`case destXYZ:`、`case destFitH:`、`case destFitBH:` 等，约 line 302–348）时，直接以 PDF 文件中指定的目标页码调用 `tileMap->getPageBoxWidth(page)`，攻击者可通过构造包含页码为 0 或超出实际页数的 link destination 的 PDF 文件触发此漏洞。
- **触发条件**: 构造一个包含 `/Dest` action（如 `/GoTo`）且目标页码为 0 或大于实际页数（如负数编码或超大整数）的 PDF，在 xpdf viewer 中打开后点击该链接或通过 JavaScript 自动触发。
- **安全影响**: 堆越界读，最坏情况下泄露堆布局信息（heap pointer leak，辅助 ASLR bypass，构成更复杂利用链的基础）；也可能触发读取未映射内存导致进程崩溃（DoS）。

## VULN: OOB Heap Read in getPageTopY/getPageBottomY/getPageLeftX/getPageRightX via PDF Destination Page Number
- **漏洞类别**: memory-safety
- **函数**: `TileMap::getPageTopY()`, `TileMap::getPageBottomY()`, `TileMap::getPageLeftX()`, `TileMap::getPageRightX()`
- **行号**: 929-1081
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 6.1 (AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted PDF file
- **外部触发路径**: `PDFCore::displayDest()` (PDFCore.cc:262-348) 使用 PDF 目标页码调用 `tileMap->getPageTopY(page)` / `tileMap->getPageLeftX(page)` → `pageY[page - 1]` / `pageH[page - 1]` / `pageW[page - 1]` / `pageX[page - 1]` 越界读
- **描述**: `getPageTopY(int page)`、`getPageBottomY(int page)`、`getPageLeftX(int page)`、`getPageRightX(int page)` 均在函数开头仅检查 `!state->getDoc()->getNumPages()`（文档页数是否为0），但**未检查 `page` 是否在 `[1, numPages]` 范围内**。随后直接以 `page - 1` 为下标访问 `pageY[]`、`pageH[]`、`pageW[]`、`pageX[]` 等堆分配数组（每个大小均为 `numPages * sizeof(int)`）。当 `page < 1` 时造成数组下标为负（堆下读）；当 `page > numPages` 时造成堆越界读。PDFCore.cc 中这四个函数均被以 PDF 链接目标页码直接调用，无二次校验。
- **触发条件**: 构造包含 `page = 0` 或 `page > numPages` 的 PDF link destination（`/GoTo`、`/GoToR` 等），在 xpdf viewer 打开后激活对应链接。
- **安全影响**: 堆越界读，可导致进程崩溃（DoS）；在内存布局可预测场景下可能辅助信息泄露。

<!-- AUDIT_PROMPT_VERSION: 1 -->
